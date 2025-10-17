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

@@
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
-	c.logger.Info("Client object created")
-	c.logger.Info("Client created")
+	// Informational lifecycle message: client created
+	c.logger.Info("client created")
+	// Debug details helpful while diagnosing client config
+	c.logger.Debug("client configuration", zap.Bool("has-custom-logger", clientCfg.Logger != nil), zap.String("codec", c.Codec()))
 	return c
 }
 
@@
 	if connectionCfg.QUICConfig == nil {
 		connectionCfg.QUICConfig = &quic.Config{
 			KeepAlivePeriod: 15 * time.Second,
 		}
 	}
 
-	conn, err := quic.DialAddr(ctx, target, connectionCfg.TLSConfig, connectionCfg.QUICConfig)
-	if err != nil {
-
-		return nil, fmt.Errorf("failed to dial: %w", err)
-	}
-	return conn, nil
+	c.logger.Debug("attempting quic dial", zap.String("target", target))
+	conn, err := quic.DialAddr(ctx, target, connectionCfg.TLSConfig, connectionCfg.QUICConfig)
+	if err != nil {
+		c.logger.Error("failed to dial target", zap.String("target", target), zap.Error(err))
+		return nil, fmt.Errorf("failed to dial: %w", err)
+	}
+	c.logger.Info("quic connection established", zap.String("target", target), zap.String("local-addr", conn.LocalAddr().String()))
+	return conn, nil
 }
 
 func (c *Client) WithLogger(logger *zap.Logger) *Client {
 	if logger != nil {
 		c.logger = logger
@@
 func (c *Client) Zap(conn quic.Connection, serviceMethod string, args ...any) (any, error) {
 	codec := c.codec
 	logger := c.logger
-
 	stream, err := conn.OpenStream()
 	if err != nil {
-		logger.Debug("Failed to open stream", zap.String("details", err.Error()))
-		logger.Error("Failed to open stream", zap.Error(err))
+		// Opening stream failed: this is an operational error
+		logger.Error("failed to open stream", zap.String("method", serviceMethod), zap.Error(err))
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
-
-	err = codec.Marshal(stream, req)
-	if err != nil {
-		logger.Debug("Error encoding request", zap.String("details", err.Error()))
-		logger.Error("Error encoding request", zap.Error(err))
-		return nil, fmt.Errorf("failed to encode request: %w", err)
-	}
+	// encode request
+	if err = codec.Marshal(stream, req); err != nil {
+		logger.Error("failed to encode request", zap.String("method", serviceMethod), zap.Error(err))
+		return nil, fmt.Errorf("failed to encode request: %w", err)
+	}
 
 	var resp ZapResponse
-	err = codec.Unmarshal(stream, &resp)
-	if err != nil {
-		logger.Debug("Error decoding response", zap.String("details", err.Error()))
-		logger.Error("Error decoding response", zap.Error(err))
-		return nil, fmt.Errorf("failed to decode response: %w", err)
-	}
+	// decode response
+	if err = codec.Unmarshal(stream, &resp); err != nil {
+		logger.Error("failed to decode response", zap.String("method", serviceMethod), zap.Error(err))
+		return nil, fmt.Errorf("failed to decode response: %w", err)
+	}
 
 	if err, ok := resp.Value.(struct{ Error string }); ok && err.Error != "" {
-		logger.Warn("RPC returned error", zap.String("error", err.Error))
+		logger.Warn("rpc returned error", zap.String("method", serviceMethod), zap.String("error", err.Error))
 		return nil, errors.New(err.Error)
 	}
 
-	logger.Info("RPC call successful", zap.String("method", serviceMethod))
+	logger.Info("rpc call successful", zap.String("method", serviceMethod))
 	return resp.Value, nil
 }

