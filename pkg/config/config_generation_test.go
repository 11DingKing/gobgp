package config

import (
	"context"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeychain(name string, sendID, receiveID uint8, secret string) oc.Keychain {
	return oc.Keychain{
		Config: oc.KeychainConfig{Name: name},
		Keys: []oc.Key{{
			Config: oc.KeyConfig{
				KeyId:           sendID,
				ReceiveId:       receiveID,
				CryptoAlgorithm: oc.CRYPTO_TYPE_HMAC_SHA_1_96,
				SecretKey:       secret,
			},
		}},
	}
}

func listDynamicNeighborRanges(t *testing.T, bgpServer interface {
	ListDynamicNeighbor(context.Context, *api.ListDynamicNeighborRequest, func(*api.DynamicNeighbor)) error
}) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := bgpServer.ListDynamicNeighbor(context.Background(), &api.ListDynamicNeighborRequest{}, func(dn *api.DynamicNeighbor) {
		result[dn.Prefix] = dn.PeerGroup
	})
	require.NoError(t, err)
	return result
}

func listNeighborSetNames(t *testing.T, bgpServer *server.BgpServer) []string {
	t.Helper()
	var names []string
	err := bgpServer.ListDefinedSet(context.Background(), &api.ListDefinedSetRequest{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
	}, func(set *api.DefinedSet) {
		names = append(names, set.Name)
	})
	require.NoError(t, err)
	return names
}

func listPolicyNames(t *testing.T, bgpServer *server.BgpServer) []string {
	t.Helper()
	var names []string
	err := bgpServer.ListPolicy(context.Background(), &api.ListPolicyRequest{}, func(p *api.Policy) {
		names = append(names, p.Name)
	})
	require.NoError(t, err)
	return names
}

// dynamicNeighborConfig builds a configuration with one peer group and the
// given dynamic neighbor ranges.
func dynamicNeighborConfig(prefixes ...string) *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.PeerGroups = []oc.PeerGroup{{
		Config: oc.PeerGroupConfig{PeerGroupName: "lan", PeerAs: 2},
	}}
	for _, prefix := range prefixes {
		cfg.DynamicNeighbors = append(cfg.DynamicNeighbors, oc.DynamicNeighbor{
			Config: oc.DynamicNeighborConfig{
				Prefix:    netip.MustParsePrefix(prefix),
				PeerGroup: "lan",
			},
		})
	}
	return cfg
}

func badPolicyConfigSet() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.PolicyDefinitions = []oc.PolicyDefinition{{
		Name: "bad",
		Statements: []oc.Statement{{
			Name: "s1",
			Conditions: oc.Conditions{
				MatchNeighborSet: oc.MatchNeighborSet{
					NeighborSet:     "ghost",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
				},
			},
		}},
	}}
	return cfg
}

// TestUpdateConfigRollsBackAppliedKeychain makes sure an object applied early
// in the reload (a TCP-AO keychain) disappears again when a later stage fails
// (a peer referencing a missing peer group). The failed attempt must leave no
// authentication resource behind and must not advance the generation.
func TestUpdateConfigRollsBackAppliedKeychain(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	current, err := InitialConfig(ctx, bgpServer, validConfig(), false)
	require.NoError(t, err)

	failed := validConfig()
	failed.Keychains = []oc.Keychain{testKeychain("fabric", 1, 2, "aW5pdGlhbA==")}
	failed.Neighbors = []oc.Neighbor{{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("10.0.0.1"),
			PeerGroup:       "missing",
			PeerAs:          2,
		},
	}}
	returned, err := UpdateConfig(ctx, bgpServer, current, failed)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to add peer")
	require.Same(t, current, returned)
	assert.Equal(t, uint64(1), bgpServer.ConfigGeneration())
	assert.Empty(t, listTcpAoKeychains(t, bgpServer), "keychain from the failed generation must be rolled back")

	// After fixing the config, reload succeeds: key chain and peer from the
	// new generation are both observable.
	fixed := validConfig()
	fixed.Keychains = []oc.Keychain{testKeychain("fabric", 1, 2, "aW5pdGlhbA==")}
	fixed.PeerGroups = []oc.PeerGroup{{
		Config: oc.PeerGroupConfig{PeerGroupName: "router", PeerAs: 2},
	}}
	fixed.Neighbors = []oc.Neighbor{{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("10.0.0.1"),
			PeerGroup:       "router",
		},
	}}
	returned, err = UpdateConfig(ctx, bgpServer, current, fixed)
	require.NoError(t, err)
	assert.NotNil(t, returned)
	assert.Equal(t, uint64(2), bgpServer.ConfigGeneration())
	chains := listTcpAoKeychains(t, bgpServer)
	assert.Contains(t, chains, "fabric")
	assert.Equal(t, map[string]string{"10.0.0.1": "router"}, listPeerGroupMembers(t, bgpServer))
}

// TestUpdateConfigDynamicNeighborGeneration verifies that dynamic neighbor
// discovery follows the committed generation: added ranges appear, removed
// ranges disappear, and a failed reload leaves the ranges of the previous
// generation untouched.
func TestUpdateConfigDynamicNeighborGeneration(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	current, err := InitialConfig(ctx, bgpServer, dynamicNeighborConfig("10.1.0.0/24"), false)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"10.1.0.0/24": "lan"}, listDynamicNeighborRanges(t, bgpServer))

	// A generation that both adds a range and carries an invalid policy fails
	// wholesale: the new range must not appear.
	failed := dynamicNeighborConfig("10.1.0.0/24", "10.2.0.0/24")
	failed.PolicyDefinitions = badPolicyConfigSet().PolicyDefinitions
	_, err = UpdateConfig(ctx, bgpServer, current, failed)
	require.Error(t, err)
	assert.Equal(t, uint64(1), bgpServer.ConfigGeneration())
	assert.Equal(t, map[string]string{"10.1.0.0/24": "lan"}, listDynamicNeighborRanges(t, bgpServer))

	// Retry from the previous generation with a valid config adds the range.
	current, err = UpdateConfig(ctx, bgpServer, current, dynamicNeighborConfig("10.1.0.0/24", "10.2.0.0/24"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), bgpServer.ConfigGeneration())
	assert.Len(t, listDynamicNeighborRanges(t, bgpServer), 2)

	// Removing a range reconciles discovery down to it.
	current, err = UpdateConfig(ctx, bgpServer, current, dynamicNeighborConfig("10.2.0.0/24"))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), bgpServer.ConfigGeneration())
	assert.Equal(t, map[string]string{"10.2.0.0/24": "lan"}, listDynamicNeighborRanges(t, bgpServer))
}

func policyBaseConfig() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.DefinedSets = oc.DefinedSets{
		NeighborSets: []oc.NeighborSet{{
			NeighborSetName:  "ns",
			NeighborInfoList: []string{"10.0.0.1"},
		}},
	}
	cfg.PolicyDefinitions = []oc.PolicyDefinition{{
		Name: "pol",
		Statements: []oc.Statement{{
			Name: "s1",
			Conditions: oc.Conditions{
				MatchNeighborSet: oc.MatchNeighborSet{
					NeighborSet:     "ns",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
				},
			},
		}},
	}}
	cfg.Global.ApplyPolicy.Config.ImportPolicyList = []string{"pol"}
	cfg.Global.ApplyPolicy.Config.DefaultImportPolicy = oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
	return cfg
}

// TestUpdateConfigRollsBackPolicy verifies that a policy stage failure after
// other objects would have been applied restores the policy objects of the
// previous generation and isolates the other objects as well.
func TestUpdateConfigRollsBackPolicy(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	current, err := InitialConfig(ctx, bgpServer, policyBaseConfig(), false)
	require.NoError(t, err)
	assert.Contains(t, listNeighborSetNames(t, bgpServer), "ns")
	assert.Contains(t, listPolicyNames(t, bgpServer), "pol")

	// New generation references an undefined neighbor set and would also add
	// a peer group. Policy validation fails before commit, so neither lands.
	failed := policyBaseConfig()
	failed.PolicyDefinitions = append(failed.PolicyDefinitions, badPolicyConfigSet().PolicyDefinitions...)
	failed.PeerGroups = []oc.PeerGroup{{
		Config: oc.PeerGroupConfig{PeerGroupName: "router", PeerAs: 2},
	}}
	_, err = UpdateConfig(ctx, bgpServer, current, failed)
	require.Error(t, err)
	assert.Equal(t, uint64(1), bgpServer.ConfigGeneration())
	assert.Contains(t, listNeighborSetNames(t, bgpServer), "ns")
	assert.NotContains(t, listPolicyNames(t, bgpServer), "bad")
	assert.Equal(t, []string{"pol"}, listPolicyNames(t, bgpServer))
	assert.Empty(t, listPeerGroupNames(t, bgpServer))
}

// TestUpdateConfigCommitsAllStages verifies that after a successful commit
// policies, peers, dynamic neighbors and authentication resources all observe
// the new generation through management queries.
func TestUpdateConfigCommitsAllStages(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	current, err := InitialConfig(ctx, bgpServer, validConfig(), false)
	require.NoError(t, err)

	desired := policyBaseConfig()
	desired.Keychains = []oc.Keychain{testKeychain("fabric", 1, 2, "aW5pdGlhbA==")}
	desired.PeerGroups = []oc.PeerGroup{{
		Config: oc.PeerGroupConfig{PeerGroupName: "lan", PeerAs: 2},
	}}
	desired.DynamicNeighbors = []oc.DynamicNeighbor{{
		Config: oc.DynamicNeighborConfig{
			Prefix:    netip.MustParsePrefix("10.1.0.0/24"),
			PeerGroup: "lan",
		},
	}}
	desired.Neighbors = []oc.Neighbor{{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("10.0.0.1"),
			PeerGroup:       "lan",
		},
	}}
	current, err = UpdateConfig(ctx, bgpServer, current, desired)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), bgpServer.ConfigGeneration())

	assert.Contains(t, listNeighborSetNames(t, bgpServer), "ns")
	assert.Equal(t, []string{"pol"}, listPolicyNames(t, bgpServer))
	assert.Contains(t, listTcpAoKeychains(t, bgpServer), "fabric")
	assert.Equal(t, []string{"lan"}, listPeerGroupNames(t, bgpServer))
	assert.Equal(t, map[string]string{"10.0.0.1": "lan"}, listPeerGroupMembers(t, bgpServer))
	assert.Equal(t, map[string]string{"10.1.0.0/24": "lan"}, listDynamicNeighborRanges(t, bgpServer))
}

// TestUpdateConfigRetryAfterFailureIsIndependent verifies that two failed
// attempts followed by a corrected one all compute from the previous
// generation: the failures neither advance the generation nor accumulate.
func TestUpdateConfigRetryAfterFailureIsIndependent(t *testing.T) {
	ctx := context.Background()
	bgpServer, _ := newTestBgpServer(t)

	current, err := InitialConfig(ctx, bgpServer, configWithValidPeerGroup(), false)
	require.NoError(t, err)

	bad1 := configWithMissingPolicySet()
	_, err = UpdateConfig(ctx, bgpServer, current, bad1)
	require.Error(t, err)

	// A second, differently broken attempt: missing peer group. It must fail
	// against the same old generation and leave the same old objects.
	bad2 := validConfig()
	bad2.Neighbors = []oc.Neighbor{{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("10.9.9.9"),
			PeerGroup:       "ghost",
			PeerAs:          2,
		},
	}}
	_, err = UpdateConfig(ctx, bgpServer, current, bad2)
	require.Error(t, err)
	assert.Equal(t, uint64(1), bgpServer.ConfigGeneration())
	assert.Equal(t, []string{"router"}, listPeerGroupNames(t, bgpServer))
	assert.Equal(t, map[string]string{"1.1.1.2": "router"}, listPeerGroupMembers(t, bgpServer))

	// Fixed reload commits once and advances by exactly one generation.
	fixed := configWithValidPeerGroup()
	fixed.Keychains = []oc.Keychain{testKeychain("edge", 3, 4, "ZWRnZS1rZXk=")}
	current, err = UpdateConfig(ctx, bgpServer, current, fixed)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), bgpServer.ConfigGeneration())
	assert.Contains(t, listTcpAoKeychains(t, bgpServer), "edge")
}
