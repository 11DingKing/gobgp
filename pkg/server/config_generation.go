// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ConfigGenerationPlan is the delta between the running configuration
// generation and the desired one. It is applied atomically by
// BgpServer.CommitConfigGeneration: every stage either commits together and
// advances the generation counter, or the server keeps serving the previous
// generation and an error is returned.
//
// Slices are processed in dependency order (keychains and peer groups before
// neighbors, neighbors before peer-group and keychain removal); the caller
// computes them from the previous and desired config sets.
type ConfigGenerationPlan struct {
	// Policy replaces the defined sets and policy definitions. nil means the
	// policy definitions do not change in this generation.
	Policy *oc.RoutingPolicy
	// GlobalApplyPolicy replaces the global import/export assignment. nil
	// means it does not change.
	GlobalApplyPolicy *oc.ApplyPolicyConfig

	// TCP-AO authentication resources.
	AddKeychains        []*api.TcpAoKeychain
	UpsertKeychains     []*api.UpdateTcpAoKeychainRequest // add (and possibly rotate) keys, before peers change
	DeleteOnlyKeychains []*api.UpdateTcpAoKeychainRequest // remove keys only, after peers stop referencing them
	RemoveKeychains     []*api.TcpAoKeychain              // whole keychains removed, after peers stop referencing them

	// Peer groups.
	AddPeerGroups    []oc.PeerGroup
	UpdatePeerGroups []oc.PeerGroup
	DeletePeerGroups []oc.PeerGroup

	// Dynamic neighbor discovery ranges.
	AddDynamicNeighbors    []oc.DynamicNeighbor
	DeleteDynamicNeighbors []oc.DynamicNeighbor

	// Static neighbors.
	AddNeighbors    []oc.Neighbor
	UpdateNeighbors []oc.Neighbor
	DeleteNeighbors []oc.Neighbor
}

// Empty reports whether the plan changes nothing.
func (p *ConfigGenerationPlan) Empty() bool {
	return p.Policy == nil &&
		p.GlobalApplyPolicy == nil &&
		len(p.AddKeychains) == 0 &&
		len(p.UpsertKeychains) == 0 &&
		len(p.DeleteOnlyKeychains) == 0 &&
		len(p.RemoveKeychains) == 0 &&
		len(p.AddPeerGroups) == 0 &&
		len(p.UpdatePeerGroups) == 0 &&
		len(p.DeletePeerGroups) == 0 &&
		len(p.AddDynamicNeighbors) == 0 &&
		len(p.DeleteDynamicNeighbors) == 0 &&
		len(p.AddNeighbors) == 0 &&
		len(p.UpdateNeighbors) == 0 &&
		len(p.DeleteNeighbors) == 0
}

// ConfigGenerationResult reports the outcome of a successful commit.
type ConfigGenerationResult struct {
	// Generation is the configuration generation now in effect.
	Generation uint64
	// NeedsSoftResetIn reports whether policy-affecting objects changed and
	// established sessions should be soft-reset inbound, following the same
	// rules the non-transactional reload used.
	NeedsSoftResetIn bool
}

// configGenerationTx is a running transaction. Every successful mutation
// records an inverse step; on failure rollback replays the steps in LIFO
// order, leaving the indexes, sessions and authentication resources of the
// previous generation in place. A transaction runs inside a single
// management operation, so accept events and other management calls cannot
// interleave with it.
type configGenerationTx struct {
	s                *BgpServer
	undo             []func()
	needsSoftResetIn bool
}

func (tx *configGenerationTx) push(undo func()) {
	tx.undo = append(tx.undo, undo)
}

func (tx *configGenerationTx) rollback() {
	for i := len(tx.undo) - 1; i >= 0; i-- {
		tx.undo[i]()
	}
}

// CommitConfigGeneration applies one configuration generation as a single
// transaction. On failure none of the plan is observable: applied objects are
// rolled back, the generation counter is left untouched and the caller can
// compute the next attempt from the previous configuration generation.
func (s *BgpServer) CommitConfigGeneration(ctx context.Context, plan *ConfigGenerationPlan) (*ConfigGenerationResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("nil config generation plan")
	}

	var result *ConfigGenerationResult
	err := s.mgmtOperation(func() error {
		tx := &configGenerationTx{s: s}
		if err := tx.apply(plan); err != nil {
			s.logger.Error("failed to commit configuration generation, rolling back",
				slog.String("Topic", "config"),
				slog.Any("Error", err))
			tx.rollback()
			return err
		}
		result = &ConfigGenerationResult{
			Generation:       s.configGeneration.Add(1),
			NeedsSoftResetIn: tx.needsSoftResetIn,
		}
		return nil
	}, true)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (tx *configGenerationTx) apply(plan *ConfigGenerationPlan) error {
	s := tx.s

	// Policy stage: definitions/defined-sets and the global assignment share
	// one snapshot so a failure restores both.
	if plan.Policy != nil || plan.GlobalApplyPolicy != nil {
		snapshot := s.policy.SnapshotState()
		tx.push(func() {
			s.policy.RestoreState(snapshot)
			s.logger.Info("restored policy of the previous configuration generation",
				slog.String("Topic", "config"))
		})
		if plan.Policy != nil {
			if err := s.resetPolicy(plan.Policy); err != nil {
				return fmt.Errorf("failed to set policies: %w", err)
			}
			tx.needsSoftResetIn = true
		}
		if plan.GlobalApplyPolicy != nil {
			if err := s.setGlobalPolicyAssignment(plan.GlobalApplyPolicy); err != nil {
				return fmt.Errorf("failed to set global policy assignment: %w", err)
			}
			tx.needsSoftResetIn = true
		}
	}

	// Keychains and new keys must exist before peers can reference them.
	for _, apiChain := range plan.AddKeychains {
		if err := tx.addKeychain(apiChain); err != nil {
			return err
		}
	}
	for _, req := range plan.UpsertKeychains {
		if err := tx.updateKeychain(req); err != nil {
			return err
		}
	}

	// Peer groups must exist before peers and dynamic ranges reference them.
	for i := range plan.AddPeerGroups {
		c := plan.AddPeerGroups[i]
		if err := s.addPeerGroup(&c); err != nil {
			return fmt.Errorf("failed to add peer group: %w", err)
		}
		name := c.Config.PeerGroupName
		tx.push(func() {
			if err := s.deletePeerGroup(name); err != nil {
				s.logger.Warn("failed to remove peer group during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", name),
					slog.Any("Error", err))
			}
		})
	}

	for i := range plan.UpdatePeerGroups {
		c := plan.UpdatePeerGroups[i]
		needs, err := s.updatePeerGroupTx(&c, tx)
		if err != nil {
			return fmt.Errorf("failed to update peer group %s: %w", c.Config.PeerGroupName, err)
		}
		tx.needsSoftResetIn = tx.needsSoftResetIn || needs
	}

	for i := range plan.AddDynamicNeighbors {
		c := plan.AddDynamicNeighbors[i]
		if err := s.addDynamicNeighbor(&c); err != nil {
			return fmt.Errorf("failed to add dynamic neighbor to peer group: %w", err)
		}
		peerGroupName := c.Config.PeerGroup
		prefix := c.Config.Prefix.String()
		tx.push(func() {
			if err := s.deleteDynamicNeighbor(peerGroupName, prefix); err != nil {
				s.logger.Warn("failed to remove dynamic neighbor during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", peerGroupName+"/"+prefix),
					slog.Any("Error", err))
			}
		})
	}

	for i := range plan.AddNeighbors {
		c := plan.AddNeighbors[i]
		if err := s.addNeighbor(&c); err != nil {
			return fmt.Errorf("failed to add peer: %w", err)
		}
		added := c
		tx.push(func() {
			if err := s.deleteNeighbor(&added, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, false); err != nil {
				// addNeighbor can fail after installing listener keys but
				// before registering the peer; remove that material too.
				s.removeNeighborListenerAuth(&added)
				s.logger.Warn("failed to remove peer during rollback",
					slog.String("Topic", "config"),
					slog.Any("Error", err))
			}
		})
	}

	for i := range plan.DeleteNeighbors {
		c := plan.DeleteNeighbors[i]
		previous, err := tx.currentNeighborConfig(&c)
		if err != nil {
			return err
		}
		if err := s.deleteNeighbor(&c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, true); err != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}
		tx.push(func() {
			restore := previous
			if err := s.addNeighbor(&restore); err != nil {
				s.logger.Warn("failed to restore peer during rollback",
					slog.String("Topic", "config"),
					slog.Any("Error", err))
			}
		})
	}

	for i := range plan.UpdateNeighbors {
		c := plan.UpdateNeighbors[i]
		needs, err := s.updateNeighborTx(&c, tx)
		if err != nil {
			return fmt.Errorf("failed to update peer: %w", err)
		}
		tx.needsSoftResetIn = tx.needsSoftResetIn || needs
	}

	// Discovery ranges disappear before their peer group, so LIFO rollback
	// re-creates the group before re-enabling the range.
	for i := range plan.DeleteDynamicNeighbors {
		c := plan.DeleteDynamicNeighbors[i]
		old := c
		peerGroupName := old.Config.PeerGroup
		prefix := old.Config.Prefix.String()
		if err := s.deleteDynamicNeighbor(peerGroupName, prefix); err != nil {
			return fmt.Errorf("failed to delete dynamic neighbor: %w", err)
		}
		tx.push(func() {
			restore := old
			if err := s.addDynamicNeighbor(&restore); err != nil {
				s.logger.Warn("failed to restore dynamic neighbor during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", peerGroupName+"/"+prefix),
					slog.Any("Error", err))
			}
		})
	}

	for i := range plan.DeletePeerGroups {
		c := plan.DeletePeerGroups[i]
		old := c
		name := old.Config.PeerGroupName
		if err := s.deletePeerGroup(name); err != nil {
			return fmt.Errorf("failed to delete peer group: %w", err)
		}
		tx.push(func() {
			restore := old
			if err := s.addPeerGroup(&restore); err != nil {
				s.logger.Warn("failed to restore peer group during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", name),
					slog.Any("Error", err))
			}
		})
	}

	// Keys and keychains can only be removed after peers stop referencing them.
	for _, req := range plan.DeleteOnlyKeychains {
		if err := tx.updateKeychain(req); err != nil {
			return err
		}
	}

	for _, apiChain := range plan.RemoveKeychains {
		name := apiChain.Name
		if s.tcpAoKeychainUsed(name) {
			return status.Errorf(codes.FailedPrecondition, "TCP-AO keychain %q is in use", name)
		}
		if _, ok := s.keychainStore.getKeychain(name); !ok {
			return status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", name)
		}
	}
	for _, apiChain := range plan.RemoveKeychains {
		name := apiChain.Name
		s.keychainStore.deleteKeychain(name)
		tx.push(func() {
			chain, err := newTcpAoKeychain(apiChain)
			if err != nil {
				s.logger.Warn("failed to rebuild TCP-AO keychain during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", name),
					slog.Any("Error", err))
				return
			}
			s.keychainStore.addKeychain(chain)
		})
	}

	return nil
}

// currentNeighborConfig resolves a neighbor from its config and returns the
// configuration currently running so a deletion can be undone.
func (tx *configGenerationTx) currentNeighborConfig(c *oc.Neighbor) (oc.Neighbor, error) {
	var pgConf *oc.PeerGroup
	if c.Config.PeerGroup != "" {
		pg, ok := tx.s.peerGroupMap[c.Config.PeerGroup]
		if !ok {
			return oc.Neighbor{}, fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
		pgConf = pg.Conf
	}
	resolved := *c
	if err := oc.SetDefaultNeighborConfigValues(&resolved, pgConf, &tx.s.bgpConfig.Global); err != nil {
		return oc.Neighbor{}, err
	}
	addr, err := resolved.ExtractNeighborAddress()
	if err != nil {
		return oc.Neighbor{}, err
	}
	peer, ok := tx.s.neighborMap[netip.MustParseAddr(addr)]
	if !ok {
		return oc.Neighbor{}, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}
	return peer.fsm.pConf.ReadCopy(), nil
}

// addKeychain validates and installs one new TCP-AO keychain. The concrete
// keychain is built here (outside live state) so a conversion or key-set
// validation failure aborts the stage without touching the store.
func (tx *configGenerationTx) addKeychain(apiChain *api.TcpAoKeychain) error {
	chain, err := newTcpAoKeychain(apiChain)
	if err != nil {
		return err
	}
	name := chain.name
	if _, exists := tx.s.keychainStore.getKeychain(name); exists {
		chain.clearKeys()
		return status.Errorf(codes.AlreadyExists, "TCP-AO keychain %q already exists", name)
	}
	tx.s.keychainStore.addKeychain(chain)
	tx.push(func() {
		tx.s.keychainStore.deleteKeychain(name)
	})
	return nil
}

// updateKeychain applies one key add/delete request on an existing keychain and
// records the inverse. Keying material of removed keys is snapshotted before
// the store zeroes it, so a rollback restores working keys.
func (tx *configGenerationTx) updateKeychain(req *api.UpdateTcpAoKeychainRequest) error {
	s := tx.s
	keychain, ok := s.keychainStore.getKeychain(req.Name)
	if !ok {
		return status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", req.Name)
	}
	for i, delKey := range req.DeleteKeys {
		sendID, receiveID, err := tcpAoKeyIDs(req.Name, i, delKey)
		if err != nil {
			return err
		}
		if _, exists := keychain.getKey(sendID, receiveID); exists && s.tcpAoKeyConfigured(req.Name, sendID) {
			return status.Errorf(codes.FailedPrecondition, "TCP-AO keychain %q key with send ID %d is configured as a preferred send key", req.Name, sendID)
		}
	}

	added, deleted, err := validateTcpAoKeychainUpdate(keychain, req)
	if err != nil {
		return err
	}
	// updateKeys zeroes the master key of deleted keys; keep private copies so
	// a rollback can install the previous keys again.
	restoreAdded := cloneTcpAoKeys(added)
	restoreDeleted := cloneTcpAoKeys(deleted)

	keychain.updateKeys(added, deleted)
	s.updateTcpAoKeychainSockets(req.Name, added, deleted)
	tx.push(func() {
		s.updateTcpAoKeychainSockets(req.Name, restoreDeleted, restoreAdded)
		keychain.updateKeys(restoreDeleted, restoreAdded)
	})
	return nil
}

// cloneTcpAoKeys deep-copies a key set, including the sensitive master key
// material, so a transaction undo does not share storage with a keychain that
// may zero it.
func cloneTcpAoKeys(keys []netutils.TCPAOKey) []netutils.TCPAOKey {
	result := make([]netutils.TCPAOKey, 0, len(keys))
	for _, key := range keys {
		key.MasterKey = bytes.Clone(key.MasterKey)
		result = append(result, key)
	}
	return result
}

// removeNeighborListenerAuth removes TCP-AO and TCP-MD5 material that
// addNeighbor installed on the listening sockets for a neighbor.
// deleteNeighbor performs the same cleanup, but only when the peer made it
// into neighborMap; a failed add can leave the material behind without a peer.
// It must be called on the management goroutine.
func (s *BgpServer) removeNeighborListenerAuth(c *oc.Neighbor) {
	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return
	}
	ipAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}
	listeners := s.listListeners(addr)
	if binding, err := s.getTcpAoKeyBinding(&c.TcpAo.Config); err == nil && binding != nil {
		if socketKeys, err := binding.socketKeys(); err == nil {
			for _, err := range deleteTcpAoKeysFromListeners(listeners, ipAddr, s.tcpAoBindInterface(c.Transport.Config), socketKeys) {
				s.logger.Warn("failed to remove TCP-AO listener keys during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", addr),
					slog.Any("Error", err))
			}
		}
	}
	if c.Config.AuthPassword != "" {
		for _, l := range listeners {
			if err := netutils.SetTCPMD5SigSockopt(l, c.Transport.Config.BindInterface, addr, ""); err != nil {
				s.logger.Warn("failed to clear md5 during rollback",
					slog.String("Topic", "config"),
					slog.String("Key", addr),
					slog.Any("Error", err))
			}
		}
	}
}
