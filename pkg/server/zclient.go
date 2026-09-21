// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

// nexthopStateCache stores a map of nexthop IP to metric value. Especially,
// the metric value of math.MaxUint32 means the nexthop is unreachable.
type nexthopStateCache map[netip.Addr]uint32

// applyToNewPathList applies cached nexthop state to newly added paths
// in-place. This is called before propagateUpdate so that paths with
// unreachable nexthops are marked invalid before being advertised.
func (m nexthopStateCache) applyToNewPathList(paths []*table.Path) {
	for _, path := range paths {
		if path == nil || path.IsWithdraw {
			continue
		}
		metric, ok := m[path.GetNexthop()]
		if !ok {
			continue
		}
		if metric == math.MaxUint32 {
			path.IsNexthopInvalid = true
		} else {
			_ = path.SetMed(int64(metric), true)
		}
	}
}

func (m nexthopStateCache) applyToPathList(paths []*table.Path) []*table.Path {
	updated := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		if path == nil || path.IsWithdraw {
			continue
		}
		metric, ok := m[path.GetNexthop()]
		if !ok {
			continue
		}
		isNexthopInvalid := metric == math.MaxUint32
		if isNexthopInvalid && path.IsNexthopInvalid {
			// Path is already correctly marked as invalid; nothing to do.
			continue
		}
		med, err := path.GetMed()
		if !isNexthopInvalid && err == nil && med == metric && !path.IsNexthopInvalid {
			// Path MED already reflects the current nexthop metric; nothing to do.
			continue
		}
		newPath := path.Clone(false)
		if isNexthopInvalid {
			newPath.IsNexthopInvalid = true
		} else {
			newPath.IsNexthopInvalid = false
			if err := newPath.SetMed(int64(metric), true); err != nil {
				continue
			}
		}
		updated = append(updated, newPath)
	}
	return updated
}

func (m nexthopStateCache) updateByNexthopUpdate(body *zebra.NexthopUpdateBody) (updated bool) {
	if len(body.Nexthops) == 0 {
		// If NEXTHOP_UPDATE message does not contain any nexthop, the given
		// nexthop is unreachable.
		if _, ok := m[body.Prefix.Prefix]; !ok {
			// Zebra will send an empty NEXTHOP_UPDATE message as the fist
			// response for the NEXTHOP_REGISTER message. Here ignores it.
			return false
		}
		m[body.Prefix.Prefix] = math.MaxUint32 // means unreachable
	} else {
		m[body.Prefix.Prefix] = body.Metric
	}
	return true
}

func (m nexthopStateCache) filterPathToRegister(paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - Withdrawn path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unspecified nexthop address
		// - Already registered nexthop
		if path == nil || path.IsWithdraw || path.IsFromExternal() {
			continue
		} else if nexthop := path.GetNexthop(); nexthop.IsUnspecified() {
			continue
		} else if _, ok := m[nexthop]; ok {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func filterOutExternalPath(paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unreachable path because invalidated by Zebra
		if path == nil || path.IsFromExternal() || path.IsNexthopInvalid {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func addLabelToNexthop(path *table.Path, cli *zebra.Client, msgFlags *zebra.MessageFlag, nexthop *zebra.Nexthop) {
	rf := path.GetFamily()
	if rf == bgp.RF_IPv4_VPN || rf == bgp.RF_IPv6_VPN {
		cli.SetLabelFlag(msgFlags, nexthop)
		switch rf {
		case bgp.RF_IPv4_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		case bgp.RF_IPv6_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		}
	}
}

func newIPRouteBody(dst []*table.Path, vrfID uint32, z *zebraClient, cli *zebra.Client) (body *zebra.IPRouteBody, isWithdraw bool) {
	version := cli.Version
	paths := filterOutExternalPath(dst)
	if len(paths) == 0 {
		return nil, false
	}
	path := paths[0]

	l := strings.SplitN(path.GetPrefix(), "/", 2)
	var prefix netip.Addr
	var nexthop zebra.Nexthop
	nexthops := make([]zebra.Nexthop, 0, len(paths))
	msgFlags := zebra.MessageNexthop
	switch path.GetFamily() {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		prefix = path.GetNlri().(*bgp.IPAddrPrefix).Prefix.Addr()
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		prefix = path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Prefix.Addr()
	default:
		return nil, false
	}
	nhVrfID := uint32(zebra.DefaultVrf)
	func() {
		z.pathVrfMu.RLock()
		defer z.pathVrfMu.RUnlock()
		for vrfPath, pathVrfID := range z.pathVrfMap {
			if path.Equal(vrfPath) {
				nhVrfID = pathVrfID
				break
			} else {
				continue
			}
		}
	}()
	for _, p := range paths {
		nexthop.Gate = p.GetNexthop()
		nexthop.VrfID = nhVrfID
		// link-local next-hop requires an interface index for kernel route installation
		nexthop.Ifindex = 0
		if nexthop.Gate.Is6() && nexthop.Gate.IsLinkLocalUnicast() {
			if zone := p.GetSource().Address.Zone(); zone != "" {
				if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
					nexthop.Ifindex = uint32(id)
				} else if ifi, err := net.InterfaceByName(zone); err == nil {
					nexthop.Ifindex = uint32(ifi.Index)
				}
			}
		}
		if nhVrfID != vrfID {
			addLabelToNexthop(path, cli, &msgFlags, &nexthop)
		}
		nexthops = append(nexthops, nexthop)
	}
	plen, _ := strconv.ParseUint(l[1], 10, 8)
	med, err := path.GetMed()
	if err == nil {
		msgFlags |= zebra.MessageMetric.ToEach(version, cli.Software)
	}
	var flags zebra.Flag
	if path.IsIBGP() {
		flags = zebra.FlagIBGP.ToEach(cli.Version, cli.Software) | zebra.FlagAllowRecursion
	} else if path.GetSource().MultihopTtl > 0 {
		flags = zebra.FlagAllowRecursion // 0x01
	}
	return &zebra.IPRouteBody{
		Type:    zebra.RouteBGP,
		Flags:   flags,
		Safi:    zebra.SafiUnicast,
		Message: msgFlags,
		Prefix: zebra.Prefix{
			Prefix:    prefix,
			PrefixLen: uint8(plen),
		},
		Nexthops: nexthops,
		Metric:   med,
	}, path.IsWithdraw
}

func newNexthopRegisterBody(paths []*table.Path, nexthopCache nexthopStateCache) *zebra.NexthopRegisterBody {
	paths = nexthopCache.filterPathToRegister(paths)
	if len(paths) == 0 {
		return nil
	}
	path := paths[0]

	family := path.GetFamily()
	nexthops := make([]*zebra.RegisteredNexthop, 0, len(paths))
	for _, p := range paths {
		nexthop := p.GetNexthop()
		var nh *zebra.RegisteredNexthop
		switch family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET,
				Prefix: nexthop,
			}
		case bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET6,
				Prefix: nexthop,
			}
		default:
			continue
		}
		nexthops = append(nexthops, nh)
	}

	// If no nexthop needs to be registered or unregistered, skips to send
	// message.
	if len(nexthops) == 0 {
		return nil
	}

	return &zebra.NexthopRegisterBody{
		Nexthops: nexthops,
	}
}

func newNexthopUnregisterBody(family uint16, prefix netip.Addr) *zebra.NexthopRegisterBody {
	return &zebra.NexthopRegisterBody{
		Nexthops: []*zebra.RegisteredNexthop{{
			Family: family,
			Prefix: prefix,
		}},
	}
}

func newPathFromIPRouteMessage(logger *slog.Logger, m *zebra.Message, version uint8, software zebra.Software) *table.Path {
	header := m.Header
	body := m.Body.(*zebra.IPRouteBody)
	family := body.Family(logger, version, software)
	isWithdraw := body.IsWithdraw(version, software)

	var nlri bgp.NLRI
	pattr := make([]bgp.PathAttributeInterface, 0)
	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	pattr = append(pattr, origin)

	logger.Debug("create path from ip route message",
		slog.String("Topic", "Zebra"),
		slog.String("RouteType", body.Type.String()),
		slog.String("Flag", body.Flags.String(version, software)),
		slog.Any("Message", body.Message),
		slog.Int("Family", int(body.Prefix.Family)),
		slog.String("Prefix", body.Prefix.Prefix.String()),
		slog.Int("PrefixLength", int(body.Prefix.PrefixLen)),
		slog.Any("Nexthop", body.Nexthops),
		slog.Uint64("Metric", uint64(body.Metric)),
		slog.Int("Distance", int(body.Distance)),
		slog.Uint64("Mtu", uint64(body.Mtu)),
		slog.String("api", header.Command.String()),
	)

	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("%s/%d", body.Prefix.Prefix.String(), body.Prefix.PrefixLen)))
	switch family {
	case bgp.RF_IPv4_UC:
		if len(body.Nexthops) > 0 {
			pa, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(body.Nexthops[0].Gate.String()))
			pattr = append(pattr, pa)
		}
	case bgp.RF_IPv6_UC:
		if len(body.Nexthops) > 0 {
			nexthop, err := netip.ParseAddr(body.Nexthops[0].Gate.String())
			if err == nil {
				attr, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
				pattr = append(pattr, attr)
			}
		}
	default:
		logger.Error("unsupport address family",
			slog.String("Topic", "Zebra"),
			slog.Int("Family", int(family)),
		)
		return nil
	}

	med := bgp.NewPathAttributeMultiExitDisc(body.Metric)
	pattr = append(pattr, med)

	path := table.NewPath(family, nil, bgp.PathNLRI{NLRI: nlri}, isWithdraw, pattr, time.Now(), false)
	path.SetIsFromExternal(true)
	return path
}

type mplsLabelParameter struct {
	rangeSize     uint32
	maps          map[uint64]*table.Bitmap
	unassignedVrf []*table.Vrf // Vrfs which are not assigned MPLS label
}

// zebraSyncCategory identifies a class of state that must be (re)synchronized
// with Zebra after a new session is established. A session must never be
// reported as healthy as long as a required category is missing.
type zebraSyncCategory uint8

const (
	zebraSyncFIBRoutes zebraSyncCategory = 1 << iota
	zebraSyncNexthopRegs
	zebraSyncMplsLabels
)

func (c zebraSyncCategory) String() string {
	categories := make([]string, 0, 3)
	if c&zebraSyncFIBRoutes != 0 {
		categories = append(categories, "fib-routes")
	}
	if c&zebraSyncNexthopRegs != 0 {
		categories = append(categories, "nexthop-registrations")
	}
	if c&zebraSyncMplsLabels != 0 {
		categories = append(categories, "mpls-labels")
	}
	return strings.Join(categories, ",")
}

// Reconnection backoff parameters. The delay grows exponentially up to the
// maximum and gets a random jitter so that gobgpd does not hammer a restarting
// Zebra in lockstep. Every wait is select-ed against the lifecycle context,
// making it cancelable at any time.
const (
	zebraDialInitialBackoff       = time.Second
	zebraDialMaxBackoff           = 60 * time.Second
	zebraHealthySessionThreshold  = 30 * time.Second
	zebraBackoffJitterDenominator = 4 // up to 25% jitter
)

func nextDialBackoff(current time.Duration) time.Duration {
	if current < zebraDialInitialBackoff {
		// First failure: start with the initial delay rather than doubling it.
		return zebraDialInitialBackoff
	}
	next := current * 2
	if next > zebraDialMaxBackoff {
		next = zebraDialMaxBackoff
	}
	return next
}

func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	jitterRange := int64(d / zebraBackoffJitterDenominator)
	if jitterRange <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(jitterRange))
}

type zebraClient struct {
	server *BgpServer

	// Immutable configuration for the lifetime of the integration.
	url                string
	protos             []string
	preferredVersion   uint8
	zapiVersions       []uint8 // ZAPI versions in fallback order
	software           zebra.Software
	nhtEnable          bool
	nhtDelay           uint8
	mplsLabelRangeSize uint32

	// Session lifecycle. ctx cancellation stops dialing, backoff waits and
	// replays immediately; done is closed when the loop goroutine exits.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// client is the transport of the currently established session. It is nil
	// while disconnected or reconnecting. All goroutines other than the loop
	// must access it through activeClient().
	sessionMu sync.RWMutex
	client    *zebra.Client

	nexthopCache nexthopStateCache
	cacheLock    sync.Mutex
	pathVrfMap   map[*table.Path]uint32 // vpn paths and nexthop vpn id
	pathVrfMu    sync.RWMutex
	mplsLabel    mplsLabelParameter

	// required/synced describe the synchronization state of the current
	// session and are reset on every (re)connect.
	syncMu   sync.Mutex
	required zebraSyncCategory
	synced   zebraSyncCategory
}

func (z *zebraClient) getPathListWithNexthopUpdate(body *zebra.NexthopUpdateBody) []*table.Path {
	rib := table.NewTableManager(z.server.logger, nil,
		z.server.globalRib.SelectionOptions(), z.server.globalRib.MultiplePathsOptions())

	var rfList []bgp.Family
	switch body.Prefix.Family {
	case syscall.AF_INET:
		rfList = []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN}
	case syscall.AF_INET6:
		rfList = []bgp.Family{bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN}
	}

	for _, rf := range rfList {
		tbl, _, err := z.server.getRib("", rf, nil)
		if err != nil {
			z.server.logger.Error("failed to get global rib",
				slog.String("Topic", "Zebra"),
				slog.String("Family", rf.String()),
				slog.String("Error", err.Error()),
			)
			continue
		}
		rib.SetTable(rf, tbl)
	}

	return rib.GetPathListWithNexthop(table.GLOBAL_RIB_NAME, rfList, body.Prefix.Prefix)
}

func (z *zebraClient) updatePathByNexthopCache(paths []*table.Path) {
	z.cacheLock.Lock()
	paths = z.nexthopCache.applyToPathList(paths)
	z.cacheLock.Unlock()
	if len(paths) > 0 {
		if err := z.server.updatePath("", paths); err != nil {
			z.server.logger.Error("failed to update nexthop reachability",
				slog.String("Topic", "Zebra"),
				slog.Any("PathList", paths),
				slog.String("Error", err.Error()),
			)
		}
	}
}

// activeClient returns the transport of the current session, or nil while
// disconnected or reconnecting.
func (z *zebraClient) activeClient() *zebra.Client {
	z.sessionMu.RLock()
	defer z.sessionMu.RUnlock()
	return z.client
}

func (z *zebraClient) setSessionClient(cli *zebra.Client) {
	z.sessionMu.Lock()
	z.client = cli
	z.sessionMu.Unlock()
}

func (z *zebraClient) clearSessionClient(cli *zebra.Client) {
	z.sessionMu.Lock()
	if z.client == cli {
		z.client = nil
	}
	z.sessionMu.Unlock()
}

// stop permanently terminates the Zebra integration: it cancels any in-flight
// dial, backoff wait and replay and closes the active session. The loop never
// reconnects afterwards.
func (z *zebraClient) stop() {
	z.cancel()
	if cli := z.activeClient(); cli != nil {
		cli.Close()
	}
}

func (z *zebraClient) wait() {
	<-z.done
}

func (z *zebraClient) resetSyncState(required zebraSyncCategory) {
	z.syncMu.Lock()
	z.required = required
	z.synced = 0
	z.syncMu.Unlock()
}

func (z *zebraClient) markSynced(categories zebraSyncCategory) {
	z.syncMu.Lock()
	wasHealthy := z.synced&z.required == z.required
	z.synced |= categories
	healthy := z.synced&z.required == z.required
	missing := z.required &^ z.synced
	z.syncMu.Unlock()
	if !wasHealthy && healthy {
		z.server.logger.Info("success to synchronize with Zebra",
			slog.String("Topic", "Zebra"))
	} else if missing != 0 {
		z.server.logger.Debug("Zebra synchronization pending",
			slog.String("Topic", "Zebra"),
			slog.String("Pending", missing.String()))
	}
}

func (z *zebraClient) isHealthy() bool {
	z.sessionMu.RLock()
	connected := z.client != nil
	z.sessionMu.RUnlock()
	z.syncMu.Lock()
	defer z.syncMu.Unlock()
	return connected && z.synced&z.required == z.required
}

// waitBackoff sleeps for the given (jittered) backoff. It returns false when
// the integration is stopped during the wait.
func (z *zebraClient) waitBackoff(d time.Duration) bool {
	timer := time.NewTimer(jitterBackoff(d))
	defer timer.Stop()
	select {
	case <-z.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// dialSession performs one connection round: it tries every configured ZAPI
// version, preserving the negotiated-version fallback order, and returns the
// first client that completes the initial protocol exchange.
func (z *zebraClient) dialSession() (*zebra.Client, error) {
	if err := z.ctx.Err(); err != nil {
		return nil, err
	}
	l := strings.SplitN(z.url, ":", 2)
	var lastErr error
	for elem, ver := range z.zapiVersions {
		if err := z.ctx.Err(); err != nil {
			return nil, err
		}
		cli, err := zebra.NewClientWithContext(z.ctx, z.server.logger, l[0], l[1], zebra.RouteBGP, ver, z.software, z.mplsLabelRangeSize)
		if err == nil && cli != nil {
			z.server.logger.Info("success to connect to Zebra",
				slog.String("Topic", "Zebra"),
				slog.Int("Version", int(ver)))
			return cli, nil
		}
		lastErr = err
		// Retry with another Zebra message version
		z.server.logger.Warn("cannot connect to Zebra with message version",
			slog.String("Topic", "Zebra"),
			slog.Int("Version", int(ver)),
			slog.String("Error", errString(err)))
		if elem < len(z.zapiVersions)-1 {
			z.server.logger.Warn("going to retry another version",
				slog.String("Topic", "Zebra"),
				slog.Int("Version", int(z.zapiVersions[elem+1])))
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("failed to connect to Zebra")
	}
	return nil, lastErr
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// drainIncoming non-blockingly processes messages already delivered by the
// current session. Processing Zebra messages while a large replay is in
// progress prevents the bounded incoming channel from filling up and stalling
// Zebra. It returns false when the session is gone or the client is stopping.
func (z *zebraClient) drainIncoming(cli *zebra.Client) bool {
	for {
		select {
		case <-z.ctx.Done():
			return false
		case msg, ok := <-cli.Receive():
			if !ok {
				return false
			}
			z.handleZebraMessage(cli, msg)
		default:
			return true
		}
	}
}

// withdrawStaleExternalRoutes removes routes that the previous (dead) Zebra
// session had redistributed into the GoBGP RIB. Zebra lost the corresponding
// state when its zserv connection went away, so keeping them would leave stale
// half-state that never gets refreshed.
func (z *zebraClient) withdrawStaleExternalRoutes() {
	paths := z.server.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0,
		[]bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
	withdrawals := make([]*table.Path, 0, len(paths))
	for _, p := range paths {
		if p.IsFromExternal() {
			withdrawals = append(withdrawals, p.Clone(true))
		}
	}
	if len(withdrawals) == 0 {
		return
	}
	if err := z.server.addPathStream("", withdrawals); err != nil {
		z.server.logger.Error("failed to withdraw stale routes from previous Zebra session",
			slog.String("Topic", "Zebra"),
			slog.Int("NumRoutes", len(withdrawals)),
			slog.String("Error", err.Error()))
	}
}

func (z *zebraClient) resetNexthopCache() {
	z.cacheLock.Lock()
	z.nexthopCache = make(nexthopStateCache)
	z.cacheLock.Unlock()
}

// replayMplsLabels invalidates label chunks of the previous Zebra process,
// queues every existing VRF for label reassignment and requests a fresh label
// chunk. The GET_LABEL_CHUNK response arrives asynchronously and completes the
// mpls-labels synchronization category.
func (z *zebraClient) replayMplsLabels(cli *zebra.Client) {
	if z.mplsLabelRangeSize == 0 || !cli.SupportMpls() {
		return
	}
	z.mplsLabel.maps = make(map[uint64]*table.Bitmap)
	queued := make([]*table.Vrf, 0)
	for _, vrf := range z.server.globalRib.GetAllVrfsMap() {
		// Labels assigned by the previous Zebra process belong to its label
		// chunk and must be reallocated from the new chunk.
		vrf.MplsLabel = 0
		queued = append(queued, vrf)
	}
	z.mplsLabel.unassignedVrf = queued
	if err := cli.SendGetLabelChunk(&zebra.GetLabelChunkBody{ChunkSize: z.mplsLabelRangeSize}); err != nil {
		z.server.logger.Error("failed to request MPLS label chunk from new Zebra session",
			slog.String("Topic", "Zebra"),
			slog.String("Error", err.Error()))
	}
}

// sendBestPathsToZebra installs one best-path (multi-path) group into every
// target VRF and (re)registers its nexthops. It returns false when the
// session broke while sending.
func (z *zebraClient) sendBestPathsToZebra(cli *zebra.Client, paths []*table.Path, vrfs map[uint32]bool) bool {
	for vrfID := range vrfs {
		if body, isWithdraw := newIPRouteBody(paths, vrfID, z, cli); body != nil {
			if err := cli.SendIPRoute(vrfID, body, isWithdraw); err != nil {
				z.server.logger.Error("failed to send ip route",
					slog.String("Topic", "Zebra"),
					slog.String("Error", err.Error()),
				)
			}
		}
		z.cacheLock.Lock()
		body := newNexthopRegisterBody(paths, z.nexthopCache)
		z.cacheLock.Unlock()
		if body != nil {
			if err := cli.SendNexthopRegister(vrfID, body, false); err != nil {
				z.server.logger.Error("failed to send nexthop register",
					slog.String("Topic", "Zebra"),
					slog.String("Error", err.Error()),
				)
			}
		}
		if !z.drainIncoming(cli) {
			return false
		}
	}
	return true
}

// replayRoutesAndNexthops rebuilds the FIB and nexthop registrations of the
// new session from the current GoBGP best-path RIB. Returns false when the
// session is gone; per-route validation errors are logged but do not abort the
// rest of the replay, matching the normal best-path event handling.
func (z *zebraClient) replayRoutesAndNexthops(cli *zebra.Client) bool {
	rib := z.server.globalRib
	if rib.UseMultiplePathsEnabled() {
		groups := rib.GetBestMultiPathList(table.GLOBAL_RIB_NAME, nil)
		vrfs := make(map[uint32]bool)
		for _, paths := range groups {
			z.server.setPathVrfIdMap(paths, vrfs)
		}
		if len(vrfs) == 0 {
			return z.drainIncoming(cli)
		}
		for _, paths := range groups {
			if !z.sendBestPathsToZebra(cli, paths, vrfs) {
				return false
			}
		}
		return true
	}

	paths := rib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil)
	vrfs := make(map[uint32]bool)
	z.server.setPathVrfIdMap(paths, vrfs)
	if len(vrfs) == 0 {
		return z.drainIncoming(cli)
	}
	for _, path := range paths {
		if !z.sendBestPathsToZebra(cli, []*table.Path{path}, vrfs) {
			return false
		}
	}
	return true
}

// drainWatcherEvents drops RIB change events that predate the resync snapshot;
// replay reads the current RIB instead, so those events are obsolete.
func drainWatcherEvents(w *watcher) {
	for {
		select {
		case <-w.ch.Out():
		case <-w.realCh:
		default:
			return
		}
	}
}

// prepareSession rebuilds every piece of session-owned state after a new
// transport session is established. It returns false when the integration is
// stopped before preparation completes.
func (z *zebraClient) prepareSession(cli *zebra.Client, w *watcher) bool {
	// Note: HELLO/ROUTER_ID_ADD messages are automatically sent to negotiate
	// the Zebra message version in zebra.NewClientWithContext().
	cli.SendInterfaceAdd()
	if !z.drainIncoming(cli) {
		return false
	}

	// Purge state owned by the previous session BEFORE subscribing to
	// redistributed routes again. Zebra only starts dumping its routes after
	// REDISTRIBUTE_ADD, so a fresh route can never be mistaken for stale
	// state of the old session.
	z.withdrawStaleExternalRoutes()
	z.resetNexthopCache()
	if z.ctx.Err() != nil {
		return false
	}

	// All RIB changes observed so far predate the resync snapshot below.
	drainWatcherEvents(w)

	for _, typ := range z.protos {
		t, err := zebra.RouteTypeFromString(typ, z.preferredVersion, z.software)
		if err != nil {
			z.server.logger.Error("failed to subscribe redistributed route type",
				slog.String("Topic", "Zebra"),
				slog.String("RouteType", typ),
				slog.String("Error", err.Error()))
			continue
		}
		cli.SendRedistribute(t, zebra.DefaultVrf)
	}
	if !z.drainIncoming(cli) {
		return false
	}

	required := zebraSyncFIBRoutes | zebraSyncNexthopRegs
	if z.mplsLabelRangeSize > 0 && cli.SupportMpls() {
		required |= zebraSyncMplsLabels
	}
	z.resetSyncState(required)

	z.replayMplsLabels(cli)
	if !z.drainIncoming(cli) {
		return false
	}

	if !z.replayRoutesAndNexthops(cli) {
		return false
	}
	z.markSynced(zebraSyncFIBRoutes | zebraSyncNexthopRegs)

	if z.ctx.Err() != nil {
		return false
	}

	z.syncMu.Lock()
	missing := z.required &^ z.synced
	z.syncMu.Unlock()
	if missing != 0 {
		// The session is usable for normal updates, but some state is still
		// pending (e.g. the MPLS label chunk response); do not call it
		// healthy. It will be retried when the chunk arrives or on the next
		// reconnect.
		z.server.logger.Warn("Zebra session is up but not fully synchronized",
			slog.String("Topic", "Zebra"),
			slog.String("Pending", missing.String()))
	}
	return true
}

// serveSession runs the normal send/recv loop for an established session. It
// returns true when the stop is intentional (integration disabled or BGP
// stopped) and false when the connection was lost and a reconnect is needed.
func (z *zebraClient) serveSession(cli *zebra.Client, w *watcher) bool {
	incoming := cli.Receive()
	events := w.Event()
	for {
		select {
		case <-z.ctx.Done():
			return true
		case msg, ok := <-incoming:
			// A closed channel means the Zebra connection was lost. Using the
			// two-value receive (instead of spinning on a nil message) avoids
			// a busy loop over the closed channel.
			if !ok {
				return false
			}
			z.handleZebraMessage(cli, msg)
		case ev, ok := <-events:
			if !ok {
				return true
			}
			z.handleWatchEvent(cli, ev)
		}
	}
}

func (z *zebraClient) handleZebraMessage(cli *zebra.Client, msg *zebra.Message) {
	switch body := msg.Body.(type) {
	case *zebra.IPRouteBody:
		if path := newPathFromIPRouteMessage(z.server.logger, msg, cli.Version, cli.Software); path != nil {
			if err := z.server.addPathStream("", []*table.Path{path}); err != nil {
				z.server.logger.Error("failed to add path from zebra",
					slog.String("Topic", "Zebra"),
					slog.Any("Path", path),
					slog.String("Error", err.Error()),
				)
			}
		}
	case *zebra.NexthopUpdateBody:
		z.cacheLock.Lock()
		updated := z.nexthopCache.updateByNexthopUpdate(body)
		z.cacheLock.Unlock()
		if !updated {
			return
		}
		paths := z.getPathListWithNexthopUpdate(body)
		if len(paths) == 0 {
			// If there is no path bound for the given nexthop, send
			// NEXTHOP_UNREGISTER message.
			z.cacheLock.Lock()
			delete(z.nexthopCache, body.Prefix.Prefix)
			z.cacheLock.Unlock()
			if err := cli.SendNexthopRegister(msg.Header.VrfID, newNexthopUnregisterBody(uint16(body.Prefix.Family), body.Prefix.Prefix), true); err != nil {
				z.server.logger.Error("failed to send nexthop unregister",
					slog.String("Topic", "Zebra"),
					slog.String("Error", err.Error()),
				)
			}
			return
		}
		z.updatePathByNexthopCache(paths)
	case *zebra.GetLabelChunkBody:
		z.server.logger.Debug("zebra GetLabelChunkBody is received",
			slog.String("Topic", "Zebra"),
			slog.Int("Start", int(body.Start)),
			slog.Int("End", int(body.End)),
		)
		startEnd := uint64(body.Start)<<32 | uint64(body.End)
		z.mplsLabel.maps[startEnd] = table.NewBitmap(int(body.End - body.Start + 1))
		failed := false
		for _, vrf := range z.mplsLabel.unassignedVrf {
			if err := z.assignAndSendVrfMplsLabel(vrf); err != nil {
				failed = true
				z.server.logger.Error("zebra failed to assign and send vrf mpls label",
					slog.String("Topic", "Zebra"),
					slog.String("Vrf", vrf.Name),
					slog.String("Error", err.Error()))
			}
		}
		z.mplsLabel.unassignedVrf = nil
		z.syncMu.Lock()
		mplsRequired := z.required&zebraSyncMplsLabels != 0
		z.syncMu.Unlock()
		if mplsRequired {
			if failed {
				// Keep the category unsynced so the session is not reported
				// healthy; the next reconnect retries the whole replay.
				z.server.logger.Warn("MPLS label synchronization incomplete; will retry on reconnect",
					slog.String("Topic", "Zebra"))
			} else {
				z.markSynced(zebraSyncMplsLabels)
			}
		}
	}
}

func (z *zebraClient) handleWatchEvent(cli *zebra.Client, ev watchEvent) {
	switch msg := ev.(type) {
	case *watchEventBestPath:
		if z.server.globalRib.UseMultiplePathsEnabled() {
			for _, paths := range msg.MultiPathList {
				z.updatePathByNexthopCache(paths)
				for i := range msg.Vrf {
					if body, isWithdraw := newIPRouteBody(paths, i, z, cli); body != nil {
						if err := cli.SendIPRoute(i, body, isWithdraw); err != nil {
							z.server.logger.Error("failed to send ip route",
								slog.String("Topic", "Zebra"),
								slog.String("Error", err.Error()),
							)
							continue
						}
					}
					z.cacheLock.Lock()
					body := newNexthopRegisterBody(paths, z.nexthopCache)
					z.cacheLock.Unlock()
					if body != nil {
						if err := cli.SendNexthopRegister(i, body, false); err != nil {
							z.server.logger.Error("failed to send nexthop register",
								slog.String("Topic", "Zebra"),
								slog.String("Error", err.Error()),
							)
							continue
						}
					}
				}
			}
		} else {
			z.updatePathByNexthopCache(msg.PathList)
			for _, path := range msg.PathList {
				for i := range msg.Vrf {
					if body, isWithdraw := newIPRouteBody([]*table.Path{path}, i, z, cli); body != nil {
						if err := cli.SendIPRoute(i, body, isWithdraw); err != nil {
							z.server.logger.Error("failed to send ip route",
								slog.String("Topic", "Zebra"),
								slog.String("Error", err.Error()),
							)
							continue
						}
					}
					z.cacheLock.Lock()
					body := newNexthopRegisterBody([]*table.Path{path}, z.nexthopCache)
					z.cacheLock.Unlock()
					if body != nil {
						if err := cli.SendNexthopRegister(i, body, false); err != nil {
							z.server.logger.Error("failed to send nexthop register",
								slog.String("Topic", "Zebra"),
								slog.String("Error", err.Error()),
							)
							continue
						}
					}
				}
			}
		}
	case *watchEventUpdate:
		z.cacheLock.Lock()
		body := newNexthopRegisterBody(msg.PathList, z.nexthopCache)
		z.cacheLock.Unlock()
		if body != nil {
			vrfID := uint32(0)
			if err := z.server.ListVrf(context.Background(), &api.ListVrfRequest{Name: msg.Neighbor.Config.Vrf}, func(v *api.Vrf) {
				vrfID = v.Id
			}); err != nil {
				z.server.logger.Error("failed to get vrf id",
					slog.String("Topic", "Zebra"),
					slog.String("Error", err.Error()),
				)
			}
			if err := cli.SendNexthopRegister(vrfID, body, false); err != nil {
				z.server.logger.Error("failed to send nexthop register",
					slog.String("Topic", "Zebra"),
					slog.String("Error", err.Error()),
				)
			}
		}
	}
}

// loop owns the entire connection lifecycle: dial with cancelable exponential
// backoff, (re)negotiate and resubscribe on every session, rebuild session
// state from the current RIB, run the normal recv/update loop, and reconnect
// when the connection drops. It only exits when the integration is stopped.
func (z *zebraClient) loop() {
	defer close(z.done)

	w, err := z.server.watch([]WatchOption{
		WatchBestPath(true),
		WatchPostUpdate(true, "", ""),
	}...)
	if err != nil {
		// the BGP server has stopped, so there is nothing left to watch.
		z.server.logger.Warn("failed to start zebra watcher",
			slog.String("Topic", "Zebra"),
			slog.String("Error", err.Error()))
		return
	}
	defer w.Stop()

	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			z.server.logger.Warn("retrying Zebra connection after backoff",
				slog.String("Topic", "Zebra"),
				slog.Duration("Backoff", backoff))
			if !z.waitBackoff(backoff) {
				return
			}
		}

		cli, err := z.dialSession()
		if err != nil {
			if z.ctx.Err() != nil {
				return
			}
			z.server.logger.Warn("failed to establish Zebra session",
				slog.String("Topic", "Zebra"),
				slog.String("Error", errString(err)))
			backoff = nextDialBackoff(backoff)
			continue
		}

		sessionStart := time.Now()
		z.setSessionClient(cli)

		prepared := z.prepareSession(cli, w)
		if !prepared {
			// Stopped while establishing or resynchronizing the session.
			z.clearSessionClient(cli)
			cli.Close()
			return
		}

		intentional := z.serveSession(cli, w)

		z.clearSessionClient(cli)
		cli.Close()
		z.resetSyncState(0)

		if intentional || z.ctx.Err() != nil {
			return
		}
		z.server.logger.Warn("connection to Zebra lost",
			slog.String("Topic", "Zebra"))

		// A session that stayed healthy for a while gets one immediate
		// reconnect attempt; flapping sessions keep backing off.
		if time.Since(sessionStart) >= zebraHealthySessionThreshold {
			backoff = 0
		} else {
			backoff = nextDialBackoff(backoff)
		}
	}
}

func newZebraClient(s *BgpServer, url string, protos []string, version uint8, nhtEnable bool, nhtDelay uint8, mplsLabelRangeSize uint32, software zebra.Software) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	var zapivers [zebra.MaxZapiVer - zebra.MinZapiVer + 1]uint8
	zapivers[0] = version
	for elem, ver := 1, zebra.MinZapiVer; elem < len(zapivers) && ver <= zebra.MaxZapiVer; elem++ {
		if version == ver && ver < zebra.MaxZapiVer {
			ver++
		}
		zapivers[elem] = ver
		ver++
	}

	ctx, cancel := context.WithCancel(context.Background())
	z := &zebraClient{
		server:             s,
		url:                url,
		protos:             append([]string(nil), protos...),
		preferredVersion:   version,
		zapiVersions:       append([]uint8(nil), zapivers[:]...),
		software:           software,
		nhtEnable:          nhtEnable,
		nhtDelay:           nhtDelay,
		mplsLabelRangeSize: mplsLabelRangeSize,
		ctx:                ctx,
		cancel:             cancel,
		done:               make(chan struct{}),
		nexthopCache:       make(nexthopStateCache),
		pathVrfMap:         make(map[*table.Path]uint32),
		mplsLabel: mplsLabelParameter{
			rangeSize: mplsLabelRangeSize,
			maps:      make(map[uint64]*table.Bitmap),
		},
		// MPLS labels are added to the required set per session when the
		// negotiated version supports them.
		required: zebraSyncFIBRoutes | zebraSyncNexthopRegs,
	}

	// Connecting, protocol negotiation and state resynchronization happen in
	// the loop goroutine, which retries with a cancelable backoff when Zebra
	// is not available yet.
	s.shutdownWG.Add(1)
	go func() {
		defer s.shutdownWG.Done()
		z.loop()
	}()
	return z, nil
}

func (z *zebraClient) assignMplsLabel() (uint32, error) {
	if z.mplsLabel.maps == nil {
		return 0, nil
	}
	var label uint32
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		l, err := bitmap.FindandSetZeroBit()
		if err == nil && start+uint32(l) <= end {
			label = start + uint32(l)
			break
		}
	}
	if label == 0 {
		return 0, fmt.Errorf("failed to assign new MPLS label")
	}
	return label, nil
}

func (z *zebraClient) assignAndSendVrfMplsLabel(vrf *table.Vrf) error {
	cli := z.activeClient()
	if cli == nil {
		// No active session (Zebra is down or reconnecting with backoff).
		// The next session resynchronizes every VRF label from a freshly
		// requested label chunk, so there is nothing to assign or send here.
		return nil
	}
	var err error
	if vrf.MplsLabel, err = z.assignMplsLabel(); vrf.MplsLabel > 0 { // success
		if err = cli.SendVrfLabel(vrf.MplsLabel, vrf.Id); err != nil {
			return err
		}
	} else if vrf.MplsLabel == 0 { // GetLabelChunk is not performed
		z.mplsLabel.unassignedVrf = append(z.mplsLabel.unassignedVrf, vrf)
	}
	return err
}

func (z *zebraClient) releaseMplsLabel(label uint32) {
	if z.mplsLabel.maps == nil {
		return
	}
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		if start <= label && label <= end {
			bitmap.Unflag(uint(label - start))
			return
		}
	}
}
