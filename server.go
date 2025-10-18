package zaprpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"math/big"
	"net"
	"reflect"
	"syscall"
	"time"
)

type Server struct {
	services map[string]any
	tlsCfg   *tls.Config
	quicCfg  *quic.Config
	tr       *quic.Transport
	codec    Codec
	logger   *zap.Logger
}

func NewServer(cfg *ServerConfig) *Server {
	var serverCfg ServerConfig
	if cfg != nil {
		serverCfg = *cfg
	}
	if serverCfg.Logger == nil {
		serverCfg.Logger = zap.NewNop()
	}
	if serverCfg.QUICConfig == nil {
		serverCfg.QUICConfig = &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
		}
	}
	if serverCfg.TLSConfig == nil {
		serverCfg.TLSConfig = generateTLSConfig()
	}
	if serverCfg.Codec == nil {
		serverCfg.Codec = &GOBCodec{}
	}
	s := &Server{
		services: make(map[string]any),
		tlsCfg:   serverCfg.TLSConfig,
		quicCfg:  serverCfg.QUICConfig,
		tr:       serverCfg.QUICTransport,
		codec:    serverCfg.Codec,
		logger:   serverCfg.Logger,
	}
	// Info-level lifecycle log
	s.logger.Info("Server created")
	// Debug log for configuration
	s.logger.Debug("Server configuration",
		zap.String("codec", s.Codec()),
		zap.Bool("custom-logger", serverCfg.Logger != nil),
	)
	return s
}

func (s *Server) RegisterService(name string, service any) {
	s.services[name] = service
	s.logger.Info("Service registered", zap.String("service", name))
}

func (s *Server) Serve(ctx context.Context) error {
	logger := s.logger
	var (
		tr           *quic.Transport
		ln           *quic.Listener
		err          error
		ownTransport bool
	)
	if s.tr != nil {
		tr = s.tr
	} else {
		tr, err = NewTransport(":6121", logger)
		if err != nil {
			logger.Error("Transport creation failed", zap.Error(err))
			return err
		}
		ownTransport = true
	}
	defer func() {
		if ownTransport && tr != nil {
			_ = tr.Close()
		}
	}()

	ln, err = tr.Listen(s.tlsCfg, s.quicCfg)
	if err != nil {
		logger.Error("Listener failed", zap.Error(err))
		return err
	}
	defer ln.Close()

	logger.Info("Server listening", zap.String("addr", ln.Addr().String()))
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			switch {
			case isGracefulClose(err) || ctx.Err() != nil:
				logger.Info("Server shutting down")
				return nil
			case isTimeout(err):
				logger.Debug("Accept timeout", zap.Error(err))
				return nil
			default:
				logger.Error("Accept failed", zap.Error(err))
				return err
			}
		}
		// Debug log for new connection
		logger.Debug("Accepted new connection", zap.String("remote-addr", conn.RemoteAddr().String()))
		go s.handleSession(ctx, conn)
	}
}

func (s *Server) handleSession(ctx context.Context, conn quic.Connection) {
	logger := s.logger
	defer func() { _ = conn.CloseWithError(0, "Server closing") }()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			switch {
			case isGracefulClose(err) || ctx.Err() != nil:
				logger.Info("Session closed", zap.Error(err))
				return
			case isTimeout(err):
				logger.Debug("Session timeout", zap.Error(err))
				return
			default:
				logger.Error("Error accepting stream", zap.Error(err))
				return
			}
		}
		logger.Debug("Accepted new stream", zap.String("stream-id", fmt.Sprintf("%d", stream.StreamID())))
		go s.handleStream(ctx, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, stream quic.Stream) {
	logger := s.logger
	codec := s.codec
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Stream panic", zap
