package provision

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// DefaultBaudRate is the standard factory provisioning UART baud rate.
	DefaultBaudRate uint32 = 115200
	// DefaultReadTimeout is the default per-command response timeout.
	DefaultReadTimeout = 3 * time.Second
)

// OpenSerial opens a raw 8N1 binary serial port (no XON/XOFF, no parity, no
// CRLF translation, no NUL-byte stripping) with bounded read timeouts.
func OpenSerial(portName string, baudRate uint32, readTimeout time.Duration) (io.ReadWriteCloser, error) {
	trimmed := strings.TrimSpace(portName)
	if trimmed == "" {
		return nil, errors.New("provision: serial port name must not be empty")
	}
	if strings.ContainsRune(trimmed, 0) {
		return nil, errors.New("provision: serial port name contains NUL byte")
	}
	if baudRate == 0 {
		return nil, errors.New("provision: baud rate must be greater than zero")
	}
	if readTimeout <= 0 {
		return nil, fmt.Errorf("provision: read timeout (%s) must be greater than zero", readTimeout)
	}
	return openSerialOS(trimmed, baudRate, readTimeout)
}
