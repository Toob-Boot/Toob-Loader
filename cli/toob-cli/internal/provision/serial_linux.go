//go:build linux

package provision

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type linuxSerialPort struct {
	mu           sync.Mutex
	fd           int
	readTimeout  time.Duration
	readDeadline time.Time
	closed       bool
}

func linuxBaudConstant(baud uint32) (uint32, error) {
	switch baud {
	case 9600:
		return unix.B9600, nil
	case 19200:
		return unix.B19200, nil
	case 38400:
		return unix.B38400, nil
	case 57600:
		return unix.B57600, nil
	case 115200:
		return unix.B115200, nil
	case 230400:
		return unix.B230400, nil
	case 460800:
		return unix.B460800, nil
	case 921600:
		return unix.B921600, nil
	default:
		return 0, fmt.Errorf("provision: unsupported baud rate %d on linux", baud)
	}
}

func openSerialOS(portName string, baudRate uint32, readTimeout time.Duration) (io.ReadWriteCloser, error) {
	baudConst, err := linuxBaudConstant(baudRate)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Open(portName, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open serial port %s: %w", portName, err)
	}

	if _, fcErr := unix.FcntlInt(uintptr(fd), unix.F_SETFL, 0); fcErr != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("clear O_NONBLOCK on %s: %w", portName, fcErr)
	}

	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("IoctlGetTermios(%s): %w", portName, err)
	}

	// cfmakeraw 8N1 binary configuration without software or hardware flow control.
	tio.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	tio.Oflag &^= unix.OPOST
	tio.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	tio.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD
	tio.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD | baudConst
	tio.Ispeed = baudConst
	tio.Ospeed = baudConst

	// VMIN=0, VTIME=1 (100ms decisecond poll) so Read respects deadlines cleanly.
	tio.Cc[unix.VMIN] = 0
	tio.Cc[unix.VTIME] = 1

	if setErr := unix.IoctlSetTermios(fd, unix.TCSETS, tio); setErr != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("IoctlSetTermios(%s): %w", portName, setErr)
	}

	_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIOFLUSH)

	return &linuxSerialPort{
		fd:          fd,
		readTimeout: readTimeout,
	}, nil
}

func (s *linuxSerialPort) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

func (s *linuxSerialPort) effectiveDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDeadline.IsZero() {
		return s.readDeadline
	}
	return time.Now().Add(s.readTimeout)
}

func (s *linuxSerialPort) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	deadline := s.effectiveDeadline()
	for {
		if time.Now().After(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := unix.Read(s.fd, p)
		if n > 0 {
			return n, nil
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return 0, err
		}
		if time.Now().After(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *linuxSerialPort) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := unix.Write(s.fd, p[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (s *linuxSerialPort) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}
