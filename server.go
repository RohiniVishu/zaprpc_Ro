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

	// Lifecycle log
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
			if isGracefulClose(err) || ctx.Err() != nil {
				logger.Info("server shutting down", zap.Error(err))
				return nil
			} else if isTimeout(err) {
				logger.Debug("accept timeout", zap.Error(err))
				continue
			} else {
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
			if isGracefulClose(err) || ctx.Err() != nil {
				logger.Info("session closed", zap.Error(err))
				return
			} else if isTimeout(err) {
				logger.Debug("session timeout", zap.Error(err))
				return
			} else {
				logger.Error("error accepting stream", zap.Error(err))
				return
			}
		}
		go s.handleStream(ctx, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, stream quic.Stream) {
	logger := s.logger
	codec := s.codec

	var req struct {
		ServiceMethod string
		Args          []any
	}
	err := codec.Unmarshal(stream, &req)
	if err != nil {
		switch {
		case isGracefulClose(err) || ctx.Err() != nil:
			logger.Debug("stream closed by peer", zap.Error(err))
		case isTimeout(err):
			logger.Debug("stream timeout", zap.Error(err))
		default:
			logger.Warn("decode failed; closing stream", zap.Error(err))
		}
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}

	resp, err := s.callMethod(req.ServiceMethod, req.Args)
	if err != nil {
		logger.Error("method call error", zap.Error(err))
		_ = codec.Marshal(stream, ZapResponse{Value: struct{ Error string }{err.Error()}})
		stream.CancelWrite(0)
		return
	}

	if err := codec.Marshal(stream, ZapResponse{Value: resp}); err != nil {
		logger.Error("encoding response failed", zap.Error(err))
		stream.CancelWrite(0)
		return
	}
}

func (s *Server) callMethod(serviceMethod string, args []any) (any, error) {
	logger := s.logger
	serviceName, methodName := parseServiceMethod(serviceMethod)
	if serviceName == "" || methodName == "" {
		logger.Error("invalid service method")
		return nil, fmt.Errorf("invalid service method: %s", serviceMethod)
	}

	service, ok := s.services[serviceName]
	if !ok {
		logger.Error("service not found", zap.String("service", serviceName))
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	method := reflect.ValueOf(service).MethodByName(methodName)
	if !method.IsValid() {
		logger.Error("method not found", zap.String("method", methodName))
		return nil, fmt.Errorf("method not found: %s", methodName)
	}

	reflectArgs := make([]reflect.Value, len(args))
	for i, arg := range args {
		reflectArgs[i] = reflect.ValueOf(arg)
	}

	results := method.Call(reflectArgs)

	if len(results) > 0 {
		lastResult := results[len(results)-1]
		if lastResult.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			results = results[:len(results)-1]
		}
	}

	if len(results) == 1 {
		return results[0].Interface(), nil
	}

	response := make([]interface{}, len(results))
	for i, result := range results {
		response[i] = result.Interface()
	}

	return response, nil
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(nil, 2048)
	certDER, _ := x509.CreateCertificate(nil, nil, nil, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
