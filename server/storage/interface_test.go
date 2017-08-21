package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Check that every provided implementation of a MetaStore actually conforms
func TestImplementationsConform(t *testing.T) {
	impls := []MetaStore{&MemStorage{}, &SQLStorage{}, &RethinkDB{}, &TUFMetaStorage{}}
	require.NotEmpty(t, impls)
}
