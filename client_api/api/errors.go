package api

import "errors"

var ErrNotImplemented = errors.New("not implemented")

type ErrUnknown struct {
	msg string
}

func NewErrorUnknown(msg string) error {
	return ErrUnknown{msg: msg}
}

func (err ErrUnknown) Error() string {
	return err.msg
}

func translateAPIError(t string, msg string) error {
	switch t {
	default:
		return NewErrorUnknown(msg)
	}
}
