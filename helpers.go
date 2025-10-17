package zaprpc

import (
	"context"
	"errors"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"go.uber.org/zap"
)

// isGracefulClose determines if an error represents a normal connection close
func isGracefulClose(err error, logger *zap.Logger) bool {
	if err == nil {
		logger.Debug("graceful close: nil error")
		return true
	}

	switch {
	case errors.Is(err, io.EOF):
		logger.Debug("graceful close: EOF")
		return true
	case errors.Is(err, net.ErrClosed):
		logger.Debug("graceful close: net.ErrClosed")
		return true
	case errors.Is(err, context.Canceled):
		logger.Debug("graceful close: context canceled")
		return true
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		logger.Debug("graceful close: QUIC application error", zap.String("error", appErr.Error()))
		return true
	}

	logger.Debug("non-graceful close detected", zap.Error(err))
	return false
}

// isTimeout determines if an error represents a timeout event
func isTimeout(err error, logger *zap.Logger) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		logger.Debug("timeout detected: context deadline exceeded")
		return true
	}

	type timeoutIface interface{ Timeout() bool }
	var te timeoutIface
	if errors.As(err, &te) && te.Timeout() {
		logger.Debug("timeout detected: implements Timeout()")
		return true
	}

	var idle *quic.IdleTimeoutError
	if errors.As(err, &idle) {
		logger.Debug("timeout detected: QUIC idle timeout", zap.String("error", idle.Error()))
		return true
	}

	logger.Debug("error is not a timeout", zap.Error(err))
	return false
}
