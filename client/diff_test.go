package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/notary/tuf"
	"github.com/theupdateframework/notary/tuf/testutils"
)

func TestDiffEmptyRepoObjs(t *testing.T) {
	first := *tuf.Repo{}
	second := *tuf.Repo{}

	res, err := diff(first, second)
	require.NoError(t, err)
	require.Len(t, res.TargetsAdded, 0)
	require.Len(t, res.TargetsRemoved, 0)
	require.Len(t, res.TargetsUpdated, 0)
	require.Len(t, res.RolesAdded, 0)
	require.Len(t, res.RolesRemoved, 0)
	require.Len(t, res.RolesUpdated, 0)
}

func TestRoleDiff(t *testing.T) {
	first := testutils.EmptyRepo("difftest", "extrarole")
	second := testutils.EmptyRepo("difftest")

	res, err := diff(first, second)
	require.NoError(t, err)
	require.Len(t, res.TargetsAdded, 0)
	require.Len(t, res.TargetsRemoved, 0)
	require.Len(t, res.TargetsUpdated, 0)
	require.Len(t, res.RolesAdded, 0)
	require.Len(t, res.RolesRemoved, 1)
	require.Len(t, res.RolesUpdated, 0)
	removedRole := res.RolesRemoved[0]
	require.Equal(t, "extrarole", removedRole.Name.String())

	// swapping around passing first and second should
	// show a role added rather than removed.
	res, err := diff(second, first)
	require.NoError(t, err)
	require.Len(t, res.TargetsAdded, 0)
	require.Len(t, res.TargetsRemoved, 0)
	require.Len(t, res.TargetsUpdated, 0)
	require.Len(t, res.RolesAdded, 1)
	require.Len(t, res.RolesRemoved, 0)
	require.Len(t, res.RolesUpdated, 0)
	removedRole := res.RolesAdded[0]
	require.Equal(t, "extrarole", removedRole.Name.String())
}
