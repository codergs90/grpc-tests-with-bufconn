package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	greetv1 "github.com/buffioconnect/gen/go/protos/greet/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func Test_GRPCInsecure(t *testing.T) {
	bufferInsecure := 1024 * 1024
	listenerInsecure := bufconn.Listen(bufferInsecure)

	s := grpc.NewServer()
	defer s.Stop()
	greetv1.RegisterGreetServiceServer(s, &greetServiceServer{})
	go func() {
		if err := s.Serve(listenerInsecure); err != nil {
			panic(err)
		}
	}()

	conn, _ := grpc.DialContext(context.Background(), "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listenerInsecure.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())

	client := greetv1.NewGreetServiceClient(conn)
	res, err := client.SayHello(context.Background(), &greetv1.GreetServiceSayHelloRequest{
		Name: "test",
	})
	require.NoError(t, err)
	require.Equal(t, res.Message, "hello test")
}

func Test_GRPC_TLS_Intermediate_CA_Knowledge(t *testing.T) {
	testSetupCA(t)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	certPool := x509.NewCertPool()
	certPool.AddCert(testData.intermediateCACert1)

	serverTLSCertificate := tls.Certificate{
		PrivateKey: testData.serverICA1CertPrivKey,
		Certificate: [][]byte{
			testData.serverICA1Cert.Raw,
		},
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "server",
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			serverTLSCertificate,
		},
		VerifyConnection: wrapperVerifyConnection(t),
	}
	tlsListner := tls.NewListener(listener, tlsConfig)

	// Server setup
	s := grpc.NewServer()
	defer s.Stop()

	greetv1.RegisterGreetServiceServer(s, &greetServiceServer{})
	go func() {
		if err := s.Serve(tlsListner); err != nil {
			panic(err)
		}
	}()

	// Client setup
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(testData.intermediateCACert1)

	clientTLSConfig := &tls.Config{
		RootCAs: clientCertPool,
		// The cert supplied by the server should have localhost in SAN
		ServerName: "localhost",
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)),
	)
	require.NoError(t, err)

	clientCtx, cancelFunc := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelFunc()

	client := greetv1.NewGreetServiceClient(conn)
	res, err := client.SayHello(clientCtx, &greetv1.GreetServiceSayHelloRequest{
		Name: "test",
	})
	require.NoError(t, err)
	require.Equal(t, res.Message, "hello test")
}

func Test_GRPC_TLS_Root_CA_Knowledge(t *testing.T) {
	testSetupCA(t)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	certPool := x509.NewCertPool()
	serverTLSCertificate := tls.Certificate{
		PrivateKey: testData.serverICA1CertPrivKey,
		Certificate: [][]byte{
			testData.serverICA1Cert.Raw,
			// Add intermediate CA so that client can just use RootCA to complete
			// TLS handshake. This also allows for an easy intermediate CA
			// rotation down the road.
			testData.intermediateCACert1.Raw,
		},
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "server",
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			serverTLSCertificate,
		},
		VerifyConnection: wrapperVerifyConnection(t),
	}
	tlsListner := tls.NewListener(listener, tlsConfig)

	// Server setup
	s := grpc.NewServer()
	defer s.Stop()

	greetv1.RegisterGreetServiceServer(s, &greetServiceServer{})
	go func() {
		if err := s.Serve(tlsListner); err != nil {
			panic(err)
		}
	}()

	// Client setup
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(testData.rootCert)

	clientTLSConfig := &tls.Config{
		RootCAs: clientCertPool,
		// The cert supplied by the server should have localhost in SAN
		ServerName: "localhost",
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)),
	)
	require.NoError(t, err)

	clientCtx, cancelFunc := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelFunc()

	client := greetv1.NewGreetServiceClient(conn)
	res, err := client.SayHello(clientCtx, &greetv1.GreetServiceSayHelloRequest{
		Name: "test",
	})
	require.NoError(t, err)
	require.Equal(t, res.Message, "hello test")
}

func Test_GRPC_MTLS_Intermediate_CA_Knowledge(t *testing.T) {

	testSetupCA(t)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	serverTLSCertificate := tls.Certificate{
		PrivateKey: testData.serverICA1CertPrivKey,
		Certificate: [][]byte{
			testData.serverICA1Cert.Raw,
			// Add intermediate CA so that client can just use RootCA to complete
			// TLS handshake. This also allows for an easy intermediate CA
			// rotation down the road.
			testData.intermediateCACert1.Raw,
		},
	}

	serverClientCACertPool := x509.NewCertPool()
	serverClientCACertPool.AddCert(testData.intermediateCACert2)
	tlsConfig := &tls.Config{
		ServerName: "server",
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			serverTLSCertificate,
		},
		ClientCAs:        serverClientCACertPool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: wrapperVerifyConnection(t),
	}
	tlsListner := tls.NewListener(listener, tlsConfig)

	// Server setup
	s := grpc.NewServer()
	defer s.Stop()

	greetv1.RegisterGreetServiceServer(s, &greetServiceServer{})
	go func() {
		if err := s.Serve(tlsListner); err != nil {
			panic(err)
		}
	}()

	// Client setup
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(testData.intermediateCACert1)

	clientTLSCertificate := tls.Certificate{
		PrivateKey: testData.clientICA2CertPrivKey,
		Certificate: [][]byte{
			testData.clientICA2Cert.Raw,
			testData.intermediateCACert2.Raw,
		},
	}

	clientTLSConfig := &tls.Config{
		RootCAs: clientCertPool,
		// The cert supplied by the server should have localhost in SAN
		ServerName: "localhost",
		Certificates: []tls.Certificate{
			clientTLSCertificate,
		},
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)),
	)
	require.NoError(t, err)

	clientCtx, cancelFunc := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelFunc()

	client := greetv1.NewGreetServiceClient(conn)
	res, err := client.SayHello(clientCtx, &greetv1.GreetServiceSayHelloRequest{
		Name: "test",
	})
	require.NoError(t, err)
	require.Equal(t, res.Message, "hello test")
}

func Test_GRPC_MTLS_Root_CA_Knowledge(t *testing.T) {

	testSetupCA(t)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(testData.rootCert)

	serverTLSCertificate := tls.Certificate{
		PrivateKey: testData.serverICA1CertPrivKey,
		Certificate: [][]byte{
			testData.serverICA1Cert.Raw,
			// Add intermediate CA so that client can just use RootCA to complete
			// TLS handshake. This also allows for an easy intermediate CA
			// rotation down the road.
			testData.intermediateCACert1.Raw,
		},
	}

	serverClientCACertPool := x509.NewCertPool()
	serverClientCACertPool.AddCert(testData.intermediateCACert2)
	tlsConfig := &tls.Config{
		ServerName: "server",
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			serverTLSCertificate,
		},
		ClientCAs:        serverCertPool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: wrapperVerifyConnection(t),
	}
	tlsListner := tls.NewListener(listener, tlsConfig)

	// Server setup
	s := grpc.NewServer()
	defer s.Stop()

	greetv1.RegisterGreetServiceServer(s, &greetServiceServer{})
	go func() {
		if err := s.Serve(tlsListner); err != nil {
			panic(err)
		}
	}()

	// Client setup
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(testData.rootCert)

	clientTLSCertificate := tls.Certificate{
		PrivateKey: testData.clientICA2CertPrivKey,
		Certificate: [][]byte{
			testData.clientICA2Cert.Raw,
			testData.intermediateCACert2.Raw,
		},
	}

	clientTLSConfig := &tls.Config{
		RootCAs: clientCertPool,
		// The cert supplied by the server should have localhost in SAN
		ServerName: "localhost",
		Certificates: []tls.Certificate{
			clientTLSCertificate,
		},
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)),
	)
	require.NoError(t, err)

	clientCtx, cancelFunc := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelFunc()

	client := greetv1.NewGreetServiceClient(conn)
	res, err := client.SayHello(clientCtx, &greetv1.GreetServiceSayHelloRequest{
		Name: "test",
	})
	require.NoError(t, err)
	require.Equal(t, res.Message, "hello test")
}

func wrapperVerifyConnection(t *testing.T) func(tls.ConnectionState) error {
	t.Log("Wrapper wrapperVerifyConnection")
	return func(state tls.ConnectionState) error {
		require.Equal(t, state.Version, uint16(tls.VersionTLS13), "tls13 no used")
		return nil
	}
}
