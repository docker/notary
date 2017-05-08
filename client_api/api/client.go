package api

import (
	"google.golang.org/grpc"

	"errors"
	"github.com/docker/notary/client"
	"github.com/docker/notary/client/changelist"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"golang.org/x/net/context"
)

type Client struct {
	client NotaryClient
	cs     signed.CryptoService
	gun    data.GUN
}

func NewClient(conn *grpc.ClientConn, gun data.GUN) *Client {
	return &Client{
		client: NewNotaryClient(conn),
		gun:    gun,
	}
}

func (c *Client) Initialize(rootKeyIDs []string, serverManagedRoles ...data.RoleName) error {
	roles := make([]string, len(serverManagedRoles))
	for index, value := range serverManagedRoles {
		roles[index] = value.String()
	}

	initMsg := &InitMessage{
		RootKeyIDs:         rootKeyIDs,
		ServerManagedRoles: &RoleNameList{Roles: roles},
		Gun:                c.gun.String(),
	}
	_, err := c.client.Initialize(context.Background(), initMsg)
	return err
}

func (c *Client) Publish() error {
	_, err := c.client.Publish(context.Background(), &GunMessage{Gun: c.gun.String()})
	return err
}

func (c *Client) DeleteTrustData(deleteRemote bool) error {
	return ErrNotImplemented
}

func (c *Client) AddTarget(target *client.Target, roles ...data.RoleName) error {
	t := &Target{
		Gun:    c.gun.String(),
		Name:   target.Name,
		Length: target.Length,
		Hashes: target.Hashes,
	}
	_, err := c.client.AddTarget(context.Background(), t)
	return err
}

func (c *Client) RemoveTarget(targetName string, roles ...data.RoleName) error {
	t := &Target{
		Gun:  c.gun.String(),
		Name: targetName,
	}
	_, err := c.client.RemoveTarget(context.Background(), t)
	return err
}

func (c *Client) ListTargets(roles ...data.RoleName) ([]*client.TargetWithRole, error) {
	rolesList := make([]string, len(roles))
	for index, value := range roles {
		rolesList[index] = value.String()
	}

	targetWithRoleList, err := c.client.ListTargets(context.Background(), &RoleNameListMessage{Roles: rolesList, Gun: c.gun.String()})
	if err != nil {
		return []*client.TargetWithRole{}, err
	}

	targets := targetWithRoleList.TargetWithRoleNameList.Targets
	res := make([]*client.TargetWithRole, len(targets))

	for index, target := range targets {
		t := target.Target
		r := target.Role

		currTarget := client.Target{
			Name:   t.GetName(),
			Hashes: data.Hashes(t.Hashes),
			Length: t.GetLength(),
		}

		currRole := data.RoleName(r)

		targetWithRole := &client.TargetWithRole{
			Target: currTarget,
			Role:   currRole,
		}

		res[index] = targetWithRole
	}

	return res, nil
}

func (c *Client) GetTargetByName(name string, roles ...data.RoleName) (*client.TargetWithRole, error) {
	rolesList := make([]string, len(roles))
	for index, value := range roles {
		rolesList[index] = value.String()
	}

	targetByNameAction := &TargetByNameAction{
		Name:  name,
		Roles: &RoleNameList{Roles: rolesList},
		Gun:   c.gun.String(),
	}

	targetWithRole, err := c.client.GetTargetByName(context.Background(), targetByNameAction)
	if err != nil {
		return nil, err
	}

	target := targetWithRole.TargetWithRole.Target
	role := targetWithRole.TargetWithRole.Role

	res := &client.TargetWithRole{
		Target: client.Target{
			Name:   target.GetName(),
			Hashes: data.Hashes(target.Hashes),
			Length: target.GetLength(),
		},
		Role: data.RoleName(role),
	}

	return res, nil
}

func (c *Client) GetAllTargetMetadataByName(name string) ([]client.TargetSignedStruct, error) {
	targetName := &TargetNameMessage{
		Name: name,
		Gun:  c.gun.String(),
	}

	targetSignedListResponse, err := c.client.GetAllTargetMetadataByName(context.Background(), targetName)
	if err != nil {
		return nil, err
	}

	targetsSigned := targetSignedListResponse.TargetSignedList.Targets

	res := make([]client.TargetSignedStruct, len(targetsSigned))
	for indexT, value := range targetsSigned {
		r := value.Role
		s := value.Signatures
		t := value.Target

		currTarget := client.Target{
			Name:   t.Name,
			Hashes: t.Hashes,
			Length: t.Length,
		}

		currSignatures := make([]data.Signature, len(s))
		for indexS, sig := range s {
			currSignature := data.Signature{
				Signature: sig.Signature,
				KeyID:     sig.KeyID,
				IsValid:   sig.IsValid,
				Method:    data.SigAlgorithm(sig.Method),
			}

			currSignatures[indexS] = currSignature
		}

		currKeys := make(map[string]data.PublicKey, len(r.Keys))
		for pubStr, pubKey := range r.Keys {
			currKeys[pubStr] = data.NewPublicKey(pubKey.Algorithm, pubKey.Public)
		}

		currRole := data.DelegationRole{
			BaseRole: data.BaseRole{
				Keys:      currKeys,
				Name:      data.RoleName(r.Name),
				Threshold: int(r.Threshold), // FIXME
			},
			Paths: r.Paths,
		}

		res[indexT] = client.TargetSignedStruct{
			Role:       currRole,
			Target:     currTarget,
			Signatures: currSignatures,
		}
	}

	return res, nil
}

func (c *Client) GetChangelist() (changelist.Changelist, error) {
	return changelist.NewMemChangelist(), errors.New("the Client API does not maintain a changelist")
}

func (c *Client) ListRoles() ([]client.RoleWithSignatures, error) {
	roleWithSigsListResp, err := c.client.ListRoles(context.Background(), &GunMessage{c.gun.String()})
	if err != nil {
		return nil, err
	}

	roleWithSignaturesList := roleWithSigsListResp.RoleWithSignaturesList.RoleWithSignatures

	res := make([]client.RoleWithSignatures, len(roleWithSignaturesList))
	for index, value := range roleWithSignaturesList {
		r := value.Role
		s := value.Signatures

		currSignatures := make([]data.Signature, len(s))
		for indexSig, sig := range value.Signatures {
			currSignature := data.Signature{
				Signature: sig.Signature,
				KeyID:     sig.KeyID,
				IsValid:   sig.IsValid,
				Method:    data.SigAlgorithm(sig.Method),
			}

			currSignatures[indexSig] = currSignature
		}

		currRole := data.Role{
			RootRole: data.RootRole{
				KeyIDs:    r.RootRole.KeyIDs,
				Threshold: int(r.RootRole.Threshold), // FIXME
			},
			Name:  data.RoleName(r.Name),
			Paths: r.Paths,
		}

		res[index] = client.RoleWithSignatures{
			Signatures: currSignatures,
			Role:       currRole,
		}
	}

	return res, nil
}

func (c *Client) GetDelegationRoles() ([]data.Role, error) {
	roleListResp, err := c.client.GetDelegationRoles(context.Background(), &GunMessage{c.gun.String()})
	if err != nil {
		return nil, err
	}

	res := make([]data.Role, len(roleListResp.RoleList.Roles))
	for index, role := range roleListResp.RoleList.Roles {
		currRole := data.Role{
			RootRole: data.RootRole{
				KeyIDs:    role.RootRole.KeyIDs,
				Threshold: int(role.RootRole.Threshold),
			},
			Name:  data.RoleName(role.Name),
			Paths: role.Paths,
		}

		res[index] = currRole
	}

	return nil, ErrNotImplemented
}

func (c *Client) AddDelegation(name data.RoleName, delegationKeys []data.PublicKey, paths []string) error {
	currDelegationKeys := make([]*PublicKey, len(delegationKeys))
	for index, key := range delegationKeys {
		currDelegationKeys[index] = &PublicKey{
			Id:        key.ID(),
			Algorithm: key.Algorithm(),
			Public:    key.Public(),
		}
	}

	addDelegationMessage := &AddDelegationMessage{
		Name:           name.String(),
		DelegationKeys: currDelegationKeys,
		Paths:          paths,
		Gun:            c.gun.String(),
	}

	_, err := c.client.AddDelegation(context.Background(), addDelegationMessage)
	return err
}

func (c *Client) AddDelegationRoleAndKeys(name data.RoleName, delegationKeys []data.PublicKey) error {
	pubKeys := make([]*PublicKey, len(delegationKeys))
	for index, delegationKey := range delegationKeys {
		pubKeys[index] = &PublicKey{
			Id:        delegationKey.ID(),
			Algorithm: delegationKey.Algorithm(),
			Public:    delegationKey.Public(),
		}
	}

	addDelegationRoleAndKeysMessage := &AddDelegationRoleAndKeysMessage{
		Name:           name.String(),
		DelegationKeys: pubKeys,
		Gun:            c.gun.String(),
	}

	_, err := c.client.AddDelegationRoleAndKeys(context.Background(), addDelegationRoleAndKeysMessage)
	return err
}

func (c *Client) AddDelegationPaths(name data.RoleName, paths []string) error {
	addDelegationPathsMessage := &AddDelegationPathsMessage{
		Name:  name.String(),
		Paths: paths,
		Gun:   c.gun.String(),
	}

	_, err := c.client.AddDelegationPaths(context.Background(), addDelegationPathsMessage)
	return err
}

func (c *Client) RemoveDelegationKeysAndPaths(name data.RoleName, keyIDs, paths []string) error {
	r := &RemoveDelegationKeysAndPathsMessage{
		Name:   name.String(),
		KeyIDs: keyIDs,
		Paths:  paths,
		Gun:    c.gun.String(),
	}

	_, err := c.client.RemoveDelegationKeysAndPaths(context.Background(), r)
	return err
}

func (c *Client) RemoveDelegationRole(name data.RoleName) error {
	r := &RemoveDelegationRoleMessage{
		Name: name.String(),
		Gun:  c.gun.String(),
	}

	_, err := c.client.RemoveDelegationRole(context.Background(), r)
	return err
}

func (c *Client) RemoveDelegationPaths(name data.RoleName, paths []string) error {
	r := &RemoveDelegationPathsMessage{
		Name:  name.String(),
		Paths: paths,
		Gun:   c.gun.String(),
	}

	_, err := c.client.RemoveDelegationPaths(context.Background(), r)
	return err
}

func (c *Client) RemoveDelegationKeys(name data.RoleName, keyIDs []string) error {
	r := &RemoveDelegationKeysMessage{
		Name:   name.String(),
		KeyIDs: keyIDs,
		Gun:    c.gun.String(),
	}

	_, err := c.client.RemoveDelegationKeys(context.Background(), r)
	return err
}

func (c *Client) ClearDelegationPaths(name data.RoleName) error {
	r := &RoleNameMessage{
		Role: name.String(),
		Gun:  c.gun.String(),
	}

	_, err := c.client.ClearDelegationPaths(context.Background(), r)
	return err
}

func (c *Client) Witness(roles ...data.RoleName) ([]data.RoleName, error) {
	roleNames := make([]string, len(roles))
	for index, roleName := range roles {
		roleNames[index] = roleName.String()
	}

	roleNameList := &RoleNameListMessage{
		Roles: roleNames,
		Gun:   c.gun.String(),
	}

	roleNameListResponse, err := c.client.Witness(context.Background(), roleNameList)
	if err != nil {
		return nil, err
	}

	roleList := roleNameListResponse.RoleNameList.Roles

	res := make([]data.RoleName, len(roleList))
	for index, role := range roleList {
		res[index] = data.RoleName(role)
	}

	return res, nil
}

func (c *Client) RotateKey(role data.RoleName, serverManagesKey bool, keyList []string) error {
	rotateKeyMessage := &RotateKeyMessage{
		Role:             role.String(),
		ServerManagesKey: serverManagesKey,
		KeyList:          keyList,
		Gun:              c.gun.String(),
	}
	_, err := c.client.RotateKey(context.Background(), rotateKeyMessage)
	return err
}

func (c *Client) SetLegacyVersions(n int) {
	// do nothing. New client API based repos only support new format root key rotation
}

func (c *Client) CryptoService() signed.CryptoService {
	return &CryptoService{client: c.client}
}

func (c *Client) GetGUN() data.GUN {
	return c.gun
}

type CryptoService struct {
	client NotaryClient
}

// Create issues a new key pair and is responsible for loading
// the private key into the appropriate signing service.
func (cs *CryptoService) Create(role data.RoleName, gun data.GUN, algorithm string) (data.PublicKey, error) {
	pub, err := cs.client.CryptoServiceCreate(
		context.Background(),
		&CryptoServiceCreateMessage{
			RoleName:  role.String(),
			Gun:       gun.String(),
			Algorithm: algorithm,
		},
	)
	if err != nil {
		return nil, err
	}
	return data.NewPublicKey(
		pub.Pubkey.Algorithm,
		pub.Pubkey.Public,
	), nil
}

// AddKey adds a private key to the specified role and gun
func (cs *CryptoService) AddKey(role data.RoleName, gun data.GUN, key data.PrivateKey) error {
	_, err := cs.client.CryptoServiceAddKey(
		context.Background(),
		&CryptoServiceAddKeyMessage{
			Gun:      gun.String(),
			RoleName: role.String(),
			Key: &PrivateKey{
				PrivKey:   key.Private(),
				PubKey:    key.Public(),
				Algorithm: key.Algorithm(),
			},
		},
	)

	return err
}

// GetKey retrieves the public key if present, otherwise it returns nil
func (cs *CryptoService) GetKey(keyID string) data.PublicKey {
	pub, err := cs.client.CryptoServiceGetKey(
		context.Background(),
		&KeyIDMessage{
			KeyID: keyID,
		},
	)
	if err != nil {
		return nil
	}
	return data.NewPublicKey(pub.Pubkey.Algorithm, pub.Pubkey.Public)
}

// GetPrivateKey retrieves the private key and role if present and retrievable,
// otherwise it returns nil and an error
func (cs *CryptoService) GetPrivateKey(keyID string) (data.PrivateKey, data.RoleName, error) {
	return nil, "", errors.New("it is not permitted to retrieve private keys from the Client API")
}

// RemoveKey deletes the specified key, and returns an error only if the key
// removal fails. If the key doesn't exist, no error should be returned.
func (cs *CryptoService) RemoveKey(keyID string) error {
	return errors.New("it is not permitted to delete keys from the Client API")
}

// ListKeys returns a list of key IDs for the role, or an empty list or
// nil if there are no keys.
func (cs *CryptoService) ListKeys(role data.RoleName) []string {
	list, err := cs.client.CryptoServiceListKeys(
		context.Background(),
		&RoleNameMessage{
			Role: role.String(),
		},
	)
	if err != nil {
		return nil
	}
	return list.KeyIDs
}

// ListAllKeys returns a map of all available signing key IDs to role, or
// an empty map or nil if there are no keys.
func (cs *CryptoService) ListAllKeys() map[string]data.RoleName {
	list, err := cs.client.CryptoServiceListAllKeys(
		context.Background(),
		&GunMessage{
			Gun: "",
		},
	)
	if err != nil {
		return nil
	}
	res := make(map[string]data.RoleName)
	for id, role := range list.KeyIDs {
		res[id] = data.RoleName(role)
	}
	return res
}
