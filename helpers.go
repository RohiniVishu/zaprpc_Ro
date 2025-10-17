package zaprpc

import (
	"context"
	"errors"
	"github.com/quic-go/quic-go"
	"io"
	"net"
)

// isGracefulClose returns true if the error is considered a normal/expected close
func isGracefulClose(err error) bool {
	if err == nil {
		return true
	}

	switch {
	case errors.Is(err, io.EOF):
		return true
	case errors.Is(err, net.ErrClosed):
		return true
	case errors.Is(err, context.Canceled):
		return true
	}

	var appErr *quic.ApplicationError
	return errors.As(err, &appErr)
}

// isTimeout returns true if the error is a timeout
func isTimeout(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	type timeoutIface interface{ Timeout() bool }
	var te timeoutIface
	if errors.As(err, &te) && te.Timeout() {
		return true
	}

	var idle *quic.IdleTimeoutError
	return errors.As(err, &idle)
}
