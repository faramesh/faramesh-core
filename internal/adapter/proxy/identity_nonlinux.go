//go:build !linux

package proxy

import (
	"fmt"
	"net/http"
)

func resolveProcessIdentity(_ *http.Request) (*ProcessIdentity, error) {
	return nil, fmt.Errorf("process identity binding is only supported on linux")
}
