//go:build windows

package provision

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dcbFlagBinary        uint32 = 0x00000001
	winNoParity          uint8  = 0
	winOneStopBit        uint8  = 0
	winPurgeRxAbort      uint32 = 0x0002
	winPurgeTxAbort      uint32 = 0x0001
	winPurgeRxClear      uint32 = 0x0008
	winPurgeTxClear      uint32 = 0x0004
	winReadPollQuantumMs uint32 = 50
)

type winSerialPort struct {
	mu           sync.Mutex
	handle       windows.Handle
	readTimeout  time.Duration
	readDeadline time.Time
	closed       bool
}

func normalizeWindowsPortPath(portName string) string {
	if strings.HasPrefix(portName, `\\.\`) {
		return portName
	}
	if strings.HasPrefix(strings.ToUpper(portName), "COM") {
		return `\\.\` + portName
	}
	return portName
}

func durationToWinTimeoutMs(d time.Duration) uint32 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 1
	}
	if ms >= math.MaxUint32 {
		return math.MaxUint32 - 1
	}
	return uint32(ms)
}

func openSerialOS(portName string, baudRate uint32, readTimeout time.Duration) (io.ReadWriteCloser, error) {
	winPath := normalizeWindowsPortPath(portName)
	pathPtr, err := windows.UTF16PtrFromString(winPath)
	if err != nil {
		return nil, fmt.Errorf("invalid serial port path %q: %w", portName, err)
	}

	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open serial port %s: %w", portName, err)
	}

	var dcb windows.DCB
	dcb.DCBlength = uint32(unsafe.Sizeof(dcb))
	if err := windows.GetCommState(h, &dcb); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("GetCommState(%s): %w", portName, err)
	}

	// Raw 8N1 binary mode: fBinary=1, all parity/flow-control/XON-XOFF/fNull flags cleared.
	dcb.BaudRate = baudRate
	dcb.ByteSize = 8
	dcb.Parity = winNoParity
	dcb.StopBits = winOneStopBit
	dcb.Flags = dcbFlagBinary
	if err := windows.SetCommState(h, &dcb); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("SetCommState(%s, %d 8N1): %w", portName, baudRate, err)
	}

	pollMs := min(durationToWinTimeoutMs(readTimeout), winReadPollQuantumMs)
	timeouts := windows.CommTimeouts{
		ReadIntervalTimeout:         10,
		ReadTotalTimeoutMultiplier:  0,
		ReadTotalTimeoutConstant:    pollMs,
		WriteTotalTimeoutMultiplier: 0,
		WriteTotalTimeoutConstant:   durationToWinTimeoutMs(readTimeout),
	}
	if err := windows.SetCommTimeouts(h, &timeouts); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("SetCommTimeouts(%s): %w", portName, err)
	}

	_ = windows.PurgeComm(h, winPurgeRxAbort|winPurgeTxAbort|winPurgeRxClear|winPurgeTxClear)

	return &winSerialPort{
		handle:      h,
		readTimeout: readTimeout,
	}, nil
}

func (s *winSerialPort) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

func (s *winSerialPort) effectiveDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDeadline.IsZero() {
		return s.readDeadline
	}
	return time.Now().Add(s.readTimeout)
}

func (s *winSerialPort) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	deadline := s.effectiveDeadline()
	for {
		if time.Now().After(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		var n uint32
		err := windows.ReadFile(s.handle, p, &n, nil)
		if n > 0 {
			return int(n), nil
		}
		if err != nil {
			return 0, err
		}
		if time.Now().After(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *winSerialPort) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		var n uint32
		err := windows.WriteFile(s.handle, p[total:], &n, nil)
		total += int(n)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (s *winSerialPort) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return windows.CloseHandle(s.handle)
}
