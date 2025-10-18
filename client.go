package zaprpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"net"
	"time"
)

type Client struct {
	codec  Codec
	logger *zap.Logger
}

func NewClient(cfg *ClientConfig) *Client {
	var clientCfg ClientConfig
	if cfg != nil {
		clientCfg = *cfg
	}
	if clientCfg.Logger == nil {
		clientCfg.Logger = zap.NewNop()
	}
	if clientCfg.Codec == nil {
		clientCfg.Codec = &GOBCodec{}
	}
	c := &Client{
		logger: clientCfg.Logger,
		codec:  clientCfg.Codec,
	}

	// Info-level lifecycle log
	c.logger.Info("Client created")
	// Debug log for configuration details
	c.logger.Debug("Client configuration",
		zap.String("codec", c.Codec()),
		zap.Bool("custom-logger", clientCfg.Logger != nil),
	)
	return c
}

func NewConn(ctx context.Context, target string, cfg *ConnectionConfig) (quic.Connection, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	var connectionCfg ConnectionConfig
	if cfg != nil {
		connectionCfg = *cfg
	}
	if connectionCfg.TLSConfig == nil {
		connectionCfg.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         host,
			InsecureSkipVerify: false,
			NextProtos:         []string{"zaprpc"},
		}
	}
	if connectionCfg.QUICConfig == nil {
		connectionCfg.QUICConfig = &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
		}
	}

	// Debug log before dialing
	fmt.Printf("Attempting QUIC dial to %s\n", target)
	conn, err := quic.DialAddr(ctx, target, connectionCfg.TLSConfig, connectionCfg.QUICConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Info log after successful connection
	fmt.Printf("QUIC connection established to %s\n", target)
	return conn, nil
}

func (c *Client) WithLogger(logger *zap.Logger) *Client {
	if logger != nil {
		c.logger = logger
	}
	return c
}

func (c *Client) WithCodec(codec Codec) *Client {
	if codec != nil {
		c.codec = codec
	}
	return c
}

func (c *Client) Codec() string {
	return c.codec.Name()
}

func (c *Client) Zap(conn quic.Connection, serviceMethod string, args ...any) (any, error) {
	codec := c.codec
	logger := c.logger

	// Debug log before opening stream
	logger.Debug("Opening stream", zap.String("method", serviceMethod))
	stream, err := conn.OpenStream()
	if err != nil {
		logger.Error("Failed to open stream", zap.String("method", serviceMethod), zap.Error(err))
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	req := struct {
		ServiceMethod string
		Args          []any
	}{
		ServiceMethod: serviceMethod,
		Args:          args,
	}

	// Debug log for encoding request
	logger.Debug("Encoding request", zap.String("method", serviceMethod))
	err = codec.Marshal(stream, req)
	if err != nil {
		logger.Error("Failed to encode request", zap.String("method", serviceMethod), zap.Error(err))
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	var resp ZapResponse
	// Debug log for decoding response
	logger.Debug("Decoding response", zap.String("method", serviceMethod))
	err = codec.Unmarshal(stream, &resp)
	if err != nil {
		logger.Error("Failed to decode response", zap.String("method", serviceMethod), zap.Error(err))
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if err, ok := resp.Value.(struct{ Error string }); ok && err.Error != "" {
		logger.Warn("RPC returned error", zap.String("method", serviceMethod), zap.String("error", err.Error))
		return nil, errors.New(err.Error)
	}

	logger.Info("RPC call successful", zap.String("method", serviceMethod))
	return resp.Value, nil
}
