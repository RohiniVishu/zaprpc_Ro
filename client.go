package zaprpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

type Client struct {
	logger *zap.Logger
	codec  Codec
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

	c.logger.Info("client created")
	c.logger.Debug("client configuration", zap.Bool("has-custom-logger", clientCfg.Logger != nil), zap.String("codec", c.Codec()))
	return c
}

func (c *Client) WithLogger(logger *zap.Logger) *Client {
	if logger != nil {
		c.logger = logger
	}
	return c
}

func (c *Client) Codec() string {
	return fmt.Sprintf("%T", c.codec)
}

func (c *Client) NewConn(ctx context.Context, target string, cfg *ConnectionConfig) (quic.Connection, error) {
	var connectionCfg ConnectionConfig
	if cfg != nil {
		connectionCfg = *cfg
	}

	if connectionCfg.TLSConfig == nil {
		connectionCfg.TLSConfig = generateTLSConfig()
	}

	if connectionCfg.QUICConfig == nil {
		connectionCfg.QUICConfig = &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
		}
	}

	c.logger.Debug("attempting quic dial", zap.String("target", target))
	conn, err := quic.DialAddr(ctx, target, connectionCfg.TLSConfig, connectionCfg.QUICConfig)
	if err != nil {
		c.logger.Error("failed to dial target", zap.String("target", target), zap.Error(err))
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	c.logger.Info("quic connection established", zap.String("target", target), zap.String("local-addr", conn.LocalAddr().String()))
	return conn, nil
}

func (c *Client) Zap(conn quic.Connection, serviceMethod string, args ...any) (any, error) {
	codec := c.codec
	logger := c.logger

	stream, err := conn.OpenStream()
	if err != nil {
		if isGracefulClose(err) {
			logger.Info("stream closed gracefully", zap.String("method", serviceMethod))
		} else if isTimeout(err) {
			logger.Debug("stream timeout", zap.String("method", serviceMethod), zap.Error(err))
		} else {
			logger.Error("failed to open stream", zap.String("method", serviceMethod), zap.Error(err))
		}
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

	if err = codec.Marshal(stream, req); err != nil {
		logger.Error("failed to encode request", zap.String("method", serviceMethod), zap.Error(err))
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	var resp ZapResponse
	if err = codec.Unmarshal(stream, &resp); err != nil {
		if isGracefulClose(err) {
			logger.Info("response stream closed gracefully", zap.String("method", serviceMethod))
		} else if isTimeout(err) {
			logger.Debug("response decode timeout", zap.String("method", serviceMethod), zap.Error(err))
		} else {
			logger.Error("failed to decode response", zap.String("method", serviceMethod), zap.Error(err))
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if err, ok := resp.Value.(struct{ Error string }); ok && err.Error != "" {
		logger.Warn("rpc returned error", zap.String("method", serviceMethod), zap.String("error", err.Error))
		return nil, errors.New(err.Error)
	}

	logger.Info("rpc call successful", zap.String("method", serviceMethod))
	return resp.Value, nil
}
