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
	"context"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGenerationTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	}))
	t.Cleanup(s.Stop)
	require.Equal(t, uint64(1), s.ConfigGeneration())
	return s
}

func listPeerAddresses(t *testing.T, s *BgpServer) map[string]struct{} {
	t.Helper()
	addrs := make(map[string]struct{})
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		addrs[p.Conf.NeighborAddress] = struct{}{}
	}))
	return addrs
}

func listKeychainNames(t *testing.T, s *BgpServer) map[string]struct{} {
	t.Helper()
	names := make(map[string]struct{})
	require.NoError(t, s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, func(c *api.TcpAoKeychain) {
		names[c.Name] = struct{}{}
	}))
	return names
}

func testNeighbor(addr, peerGroup string, peerAS uint32) oc.Neighbor {
	return oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr(addr),
			PeerGroup:       peerGroup,
			PeerAs:          peerAS,
		},
	}
}

// TestCommitGenerationAddRollback verifies that a peer group and a peer added
// earlier in the transaction are removed again when a later peer add fails,
// and that the generation counter does not move.
func TestCommitGenerationAddRollback(t *testing.T) {
	s := newGenerationTestServer(t)

	plan := &ConfigGenerationPlan{
		AddPeerGroups: []oc.PeerGroup{{
			Config: oc.PeerGroupConfig{PeerGroupName: "router", PeerAs: 2},
		}},
		AddNeighbors: []oc.Neighbor{
			testNeighbor("10.0.0.1", "router", 0),
			testNeighbor("10.0.0.2", "missing", 0),
		},
	}
	_, err := s.CommitConfigGeneration(context.Background(), plan)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to add peer")

	assert.Equal(t, uint64(1), s.ConfigGeneration())
	assert.Empty(t, listPeerAddresses(t, s))
	var pgNames []string
	require.NoError(t, s.ListPeerGroup(context.Background(), &api.ListPeerGroupRequest{}, func(pg *api.PeerGroup) {
		pgNames = append(pgNames, pg.Conf.PeerGroupName)
	}))
	assert.Empty(t, pgNames)

	// The same, corrected plan commits and advances exactly one generation.
	plan2 := &ConfigGenerationPlan{
		AddPeerGroups: []oc.PeerGroup{{
			Config: oc.PeerGroupConfig{PeerGroupName: "router", PeerAs: 2},
		}},
		AddNeighbors: []oc.Neighbor{testNeighbor("10.0.0.1", "router", 0)},
	}
	result, err := s.CommitConfigGeneration(context.Background(), plan2)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), result.Generation)
	assert.Contains(t, listPeerAddresses(t, s), "10.0.0.1")
}

// TestCommitGenerationDeleteRollback verifies that deleting a peer and then
// failing at the neighbor update stage re-creates the deleted peer from the
// previous generation so the indexes match the old configuration again.
func TestCommitGenerationDeleteRollback(t *testing.T) {
	s := newGenerationTestServer(t)

	setup := &ConfigGenerationPlan{
		AddPeerGroups: []oc.PeerGroup{{
			Config: oc.PeerGroupConfig{PeerGroupName: "router", PeerAs: 2},
		}},
		AddNeighbors: []oc.Neighbor{testNeighbor("10.0.0.1", "router", 0)},
	}
	_, err := s.CommitConfigGeneration(context.Background(), setup)
	require.NoError(t, err)
	assert.Contains(t, listPeerAddresses(t, s), "10.0.0.1")

	// Delete the existing peer and update a nonexistent one. The update stage
	// runs after deletions, so rollback must re-add 10.0.0.1.
	failing := &ConfigGenerationPlan{
		DeleteNeighbors: []oc.Neighbor{testNeighbor("10.0.0.1", "router", 0)},
		UpdateNeighbors: []oc.Neighbor{testNeighbor("10.0.0.9", "router", 0)},
	}
	_, err = s.CommitConfigGeneration(context.Background(), failing)
	require.Error(t, err)
	assert.Equal(t, uint64(2), s.ConfigGeneration())
	assert.Contains(t, listPeerAddresses(t, s), "10.0.0.1", "deleted peer must be restored on rollback")
}

// TestCommitGenerationKeychainRollback verifies that a keychain added before a
// failing keychain validation is removed again, leaving no authentication
// resource from the failed generation.
func TestCommitGenerationKeychainRollback(t *testing.T) {
	s := newGenerationTestServer(t)

	plan := &ConfigGenerationPlan{
		AddKeychains: []*api.TcpAoKeychain{
			{
				Name: "good",
				Keys: []*api.TcpAoKey{{
					SendId:    1,
					ReceiveId: 2,
					Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
					MasterKey: []byte("key-one"),
				}},
			},
			{
				// duplicate send ID fails key-set validation
				Name: "bad",
				Keys: []*api.TcpAoKey{
					{
						SendId:    1,
						ReceiveId: 2,
						Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
						MasterKey: []byte("key-two"),
					},
					{
						SendId:    1,
						ReceiveId: 3,
						Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
						MasterKey: []byte("key-three"),
					},
				},
			},
		},
	}
	_, err := s.CommitConfigGeneration(context.Background(), plan)
	require.Error(t, err)
	assert.Equal(t, uint64(1), s.ConfigGeneration())
	assert.Empty(t, listKeychainNames(t, s))

	// A retry with only the valid chain succeeds.
	retry := &ConfigGenerationPlan{
		AddKeychains: []*api.TcpAoKeychain{{
			Name: "good",
			Keys: []*api.TcpAoKey{{
				SendId:    1,
				ReceiveId: 2,
				Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
				MasterKey: []byte("key-one"),
			}},
		}},
	}
	_, err = s.CommitConfigGeneration(context.Background(), retry)
	require.NoError(t, err)
	assert.Contains(t, listKeychainNames(t, s), "good")
}
