package zaprpc

import (
	"crypto/tls"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

type ClientConfig struct {
	Logger *zap.Logger
	Codec  Codec
}

type ServerConfig struct {
	Logger    *zap.Logger
	Codec     Codec
	TLSConfig *tls.Config
}

type ConnectionConfig struct {
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
}
