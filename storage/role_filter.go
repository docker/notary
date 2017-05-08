package storage

import (
	"github.com/docker/notary/tuf/data"
)

// RoleFilter is a wrapper around a MetadataStore which filters requested roles.
// It references the set of roles it contains for export and import and the cache
// from the reference repository.
type RoleFilter struct {
	MetadataStore
	Roles []data.RoleName
}

// NewRoleFilter returns a new instance of an ExportStore
func NewRoleFilter(baseDir, fileExt string, roles []data.RoleName) (
	*RoleFilter, error) {
	store, err := NewFileStore(baseDir, fileExt)
	if err != nil {
		return nil, err
	}

	return &RoleFilter{
		MetadataStore: store,
		Roles:         roles,
	}, nil
}

// GetSized returns the file requested by name, up to size bytes
func (e *RoleFilter) GetSized(name string, size int64) ([]byte, error) {
	if len(e.Roles) == 0 {
		return e.MetadataStore.GetSized(name, size)
	}

	for _, role := range e.Roles {
		if name == role.String() {
			jsonBytes, err := e.MetadataStore.GetSized(name, size)
			if err != nil {
				return nil, err
			}

			return jsonBytes, nil
		}
	}

	return nil, ErrMetaNotFound{Resource: name}
}

// Set sets the value for the provided name
func (e *RoleFilter) Set(name string, blob []byte) error {
	if len(e.Roles) == 0 {
		return e.MetadataStore.Set(name, blob)
	}

	for _, role := range e.Roles {
		if name == role.String() {
			return e.MetadataStore.Set(name, blob)
		}
	}

	return nil
}

// SetMulti sets the values for all names in the metas map
func (e *RoleFilter) SetMulti(metas map[string][]byte) error {
	for role, blob := range metas {
		err := e.Set(role, blob)
		if err != nil {
			return err
		}
	}

	return nil
}
