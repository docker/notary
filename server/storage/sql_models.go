package storage

import (
	"time"

	"github.com/jinzhu/gorm"
)

const (
	changeCategoryUpdate   = "update"
	changeCategoryDeletion = "deletion"
)

// TUFFileTableName returns the name used for the tuf file table
const TUFFileTableName = "tuf_files"

// ChangefeedTableName returns the name used for the changefeed table
const ChangefeedTableName = "changefeed"

// ChannelTableName returns the name used for the channel table
const ChannelTableName = "channels"

// Channel is a particular view of TUF Metadata, e.g. a set of partially signed metadata
type Channel struct {
	ID   uint   `gorm:"primary_key" sql:"not null" json:",string"`
	Name string `gorm:"column:name" sql:"type:varchar(255);not null"`
}

// TableName sets a specific table name for TUFFile
func (c Channel) TableName() string {
	return ChannelTableName
}

var (
	// Published is the channel all fully signed, validated metadata lives in
	Published = Channel{
		ID:   1,
		Name: "published",
	}

	// Staged is the channel all partially signed metadata lives in
	Staged = Channel{
		ID:   2,
		Name: "staged",
	}
)

// TUFFile represents a TUF file in the database
type TUFFile struct {
	gorm.Model
	Gun      string     `sql:"type:varchar(255);not null"`
	Role     string     `sql:"type:varchar(255);not null"`
	Version  int        `sql:"not null"`
	SHA256   string     `gorm:"column:sha256" sql:"type:varchar(64);"`
	Data     []byte     `sql:"type:longblob;not null"`
	Channels []*Channel `gorm:"many2many:channels_tuf_files"`
}

// TableName sets a specific table name for TUFFile
func (g TUFFile) TableName() string {
	return TUFFileTableName
}

// Change defines the the fields required for an object in the changefeed
type Change struct {
	ID        uint `gorm:"primary_key" sql:"not null" json:",string"`
	CreatedAt time.Time
	GUN       string `gorm:"column:gun" sql:"type:varchar(255);not null"`
	Version   int    `sql:"not null"`
	SHA256    string `gorm:"column:sha256" sql:"type:varchar(64);"`
	Category  string `sql:"type:varchar(20);not null;"`
}

// TableName sets a specific table name for Changefeed
func (c Change) TableName() string {
	return ChangefeedTableName
}

type channelsTufFiles struct {
	ChannelID int `gorm:"type:integer;primary_key" sql:"type:int REFERENCES channels(id)"`
	TufFileID int `gorm:"type:integer;primary_key" sql:"type int REFERENCES tuf_files(id)"`
}

// CreateChannelTable creates the DB table for Channel
func CreateChannelTable(db gorm.DB) error {
	// Necessary until this issue is fixed: https://github.com/jinzhu/gorm/issues/653#issuecomment-153782846
	relation := gorm.Relationship{}
	relation.Kind = "many2many"
	relation.ForeignFieldNames = []string{"id"}
	relation.ForeignDBNames = []string{"channel_id"}
	relation.AssociationForeignDBNames = []string{"tuf_file_id"}
	relation.AssociationForeignFieldNames = []string{"id"}
	handler := gorm.JoinTableHandler{}
	db.SetJoinTableHandler(&TUFFile{}, "Channels", &handler)

	query := db.AutoMigrate(&channelsTufFiles{})
	if query.Error != nil {
		return query.Error
	}
	query = db.AutoMigrate(&Channel{})
	if query.Error != nil {
		return query.Error
	}
	query = db.FirstOrCreate(&Published)
	if query.Error != nil {
		return query.Error
	}
	query = db.FirstOrCreate(&Staged)
	if query.Error != nil {
		return query.Error
	}

	return nil
}

// CreateTUFTable creates the DB table for TUFFile
func CreateTUFTable(db gorm.DB) error {
	query := db.AutoMigrate(&TUFFile{})
	return query.Error
}

// CreateChangefeedTable creates the DB table for Changefeed
func CreateChangefeedTable(db gorm.DB) error {
	query := db.AutoMigrate(&Change{})
	return query.Error
}
