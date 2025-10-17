package zaprpc

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"reflect"
	"syscall"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

type Server struct {
	tr       *quic.Transport
	quicCfg  *quic.Config
	tlsCfg   *tls.Config
	logger   *zap.Logger
	services map[string]any
	codec    Codec
}

func NewServer(cfg *ServerConfig) *Server {
	serverCfg := ServerConfig{}
	if cfg != nil {
		serverCfg = *cfg
	}

	if serverCfg.Logger == nil {
		serverCfg.Logger = zap.NewNop()
	}
	if serverCfg.TLSConfig == nil {
		serverCfg.TLSConfig = generateTLSConfig()
	}
	if serverCfg.Codec == nil {
		serverCfg.Codec = &GOBCodec{}
	}

	s := &Server{
		codec:    serverCfg.Codec,
		logger:   serverCfg.Logger,
		services: make(map[string]any),
	}

	s.logger.Info("server created")
	s.logger.Debug("server configuration", zap.Bool("has-custom-logger", serverCfg.Logger != nil), zap.String("codec", s.Codec()))
	return s
}

func (s *Server) WithLogger(logger *zap.Logger) *Server {
	if logger != nil {
		s.logger = logger
	}
	return s
}

func (s *Server) Codec() string {
	return fmt.Sprintf("%T", s.codec)
}

func (s *Server) RegisterService(name string, service any) {
	s.services[name] = service
	s.logger.Info("service registered", zap.String("service", name))
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
			logger.Error("transport creation failed", zap.Error(err))
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
		logger.Error("listener creation failed", zap.Error(err))
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			switch {
			case isGracefulClose(err) || ctx.Err() != nil:
				logger.Info("server shutting down", zap.Error(err))
				return nil
			case isTimeout(err):
				logger.Debug("accept timeout", zap.Error(err))
				continue
			default:
				logger.Error("accept failed", zap.Error(err))
				continue
			}
		}
		go s.handleSession(ctx, conn)
	}
}

func (s *Server) handleSession(ctx context.Context, conn quic.Connection) {
	logger := s.logger
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			switch {
			case isGracefulClose(err) || ctx.Err() != nil:
				logger.Info("session closed", zap.Error(err))
				return
			case isTimeout(err):
				logger.Debug("session timeout", zap.Error(err))
				return
			default:
				logger.Error("error accepting stream", zap.Error(err))
				return
			}
		}
