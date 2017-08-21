package storage

import "github.com/docker/notary/tuf/data"

// MetaUpdate packages up the fields required to update a TUF record
type MetaUpdate struct {
	Role     data.RoleName
	Version  int
	Data     []byte
	Channels []*Channel
}

func setDefaultChannels(update *MetaUpdate) {
	if len(update.Channels) == 0 {
		update.Channels = []*Channel{&Published}
	}
}

// IsPublished returns whether Published is in the set of channels
func IsPublished(channels []*Channel) bool {
	return InChannel(channels, Published)
}

// InChannel returns whether a specific channel is in a set of channels
func InChannel(channels []*Channel, channel Channel) bool {
	for _, c := range channels {
		if c.ID == channel.ID {
			return true
		}
	}
	return false
}
