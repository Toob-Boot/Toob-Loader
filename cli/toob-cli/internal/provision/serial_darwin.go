//go:build darwin

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

const darwinIOSSIOSPEED = 0x80085402

type darwinSerialPort struct {
	mu           sync.Mutex
	fd           int
	readTimeout  time.Duration
	readDeadline time.Time
	closed       bool
}

func darwinBaudConstant(baud uint32) (uint64, bool, error) {
	switch baud {
	case 9600:
		return unix.B9600, false, nil
	case 19200:
		return unix.B19200, false, nil
	case 38400:
		return unix.B38400, false, nil
	case 57600:
		return unix.B57600, false, nil
	case 115200:
		return unix.B115200, false, nil
	case 230400:
		return unix.B230400, false, nil
	case 460800, 921600:
		return unix.B230400, true, nil
	default:
		return 0, false, fmt.Errorf("provision: unsupported baud rate %d on darwin", baud)
	}
}

func openSerialOS(portName string, baudRate uint32, readTimeout time.Duration) (io.ReadWriteCloser, error) {
	baudConst, needCustomSpeed, err := darwinBaudConstant(baudRate)
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

	tio, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("IoctlGetTermios(%s): %w", portName, err)
	}

	tio.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	tio.Oflag &^= unix.OPOST
	tio.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	tio.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB
	tio.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD
	tio.Ispeed = baudConst
	tio.Ospeed = baudConst

	tio.Cc[unix.VMIN] = 0
	tio.Cc[unix.VTIME] = 1

	if setErr := unix.IoctlSetTermios(fd, unix.TIOCSETA, tio); setErr != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("IoctlSetTermios(%s): %w", portName, setErr)
	}

	if needCustomSpeed {
		if speedErr := unix.IoctlSetPointerInt(fd, darwinIOSSIOSPEED, int(baudRate)); speedErr != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("IOSSIOSPEED(%s, %d): %w", portName, baudRate, speedErr)
		}
	}

	return &darwinSerialPort{
		fd:          fd,
		readTimeout: readTimeout,
	}, nil
}

func (s *darwinSerialPort) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

func (s *darwinSerialPort) effectiveDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDeadline.IsZero() {
		return s.readDeadline
	}
	return time.Now().Add(s.readTimeout)
}

func (s *darwinSerialPort) Read(p []byte) (int, error) {
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

func (s *darwinSerialPort) Write(p []byte) (int, error) {
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

func (s *darwinSerialPort) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}
