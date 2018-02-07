package client

import (
	"github.com/theupdateframework/notary/tuf"
	"github.com/theupdateframework/notary/tuf/data"
)

func getAllTargetMetadataByName(repo tuf.Repo, name string) ([]TargetSignedStruct, error) {
	var targetInfoList []TargetSignedStruct

	// Define a visitor function to find the specified target
	getAllTargetInfoByNameVisitorFunc := func(tgt *data.SignedTargets, validRole data.DelegationRole) interface{} {
		if tgt == nil {
			return nil
		}
		// We found a target and validated path compatibility in our walk,
		// so add it to our list if we have a match
		// if we have an empty name, add all targets, else check if we have it
		var targetMetaToAdd data.Files
		if name == "" {
			targetMetaToAdd = tgt.Signed.Targets
		} else {
			if meta, ok := tgt.Signed.Targets[name]; ok {
				targetMetaToAdd = data.Files{name: meta}
			}
		}

		for targetName, resultMeta := range targetMetaToAdd {
			targetInfo := TargetSignedStruct{
				Role:       validRole,
				Target:     Target{Name: targetName, Hashes: resultMeta.Hashes, Length: resultMeta.Length, Custom: resultMeta.Custom},
				Signatures: tgt.Signatures,
			}
			targetInfoList = append(targetInfoList, targetInfo)
		}
		// continue walking to all child roles
		return nil
	}

	// Check that we didn't error, and that we found the target at least once
	if err := repo.WalkTargets(name, "", getAllTargetInfoByNameVisitorFunc); err != nil {
		return nil, err
	}
	if len(targetInfoList) == 0 {
		return nil, ErrNoSuchTarget(name)
	}
	return targetInfoList, nil
}
