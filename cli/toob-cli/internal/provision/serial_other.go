//go:build !windows && !linux && !darwin

package provision

import (
	"fmt"
	"io"
	"runtime"
	"time"
)

func openSerialOS(_ string, _ uint32, _ time.Duration) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("provision: raw serial port is not supported on %s", runtime.GOOS)
}
