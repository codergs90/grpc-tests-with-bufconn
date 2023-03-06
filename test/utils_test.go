package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cpkix "github.com/square/certstrap/pkix"
	"github.com/stretchr/testify/require"
)

// TestData ...
type TestData struct {
	rootKey  *cpkix.Key
	rootCert *x509.Certificate

	intermediateCAKey1  *cpkix.Key
	intermediateCACert1 *x509.Certificate

	intermediateCAKey2  *cpkix.Key
	intermediateCACert2 *x509.Certificate

	// sever cert ICA1
	serverICA1Cert        *x509.Certificate
	serverICA1CertByte    []byte
	serverICA1CertPrivKey *rsa.PrivateKey

	// client cert ICA1
	clientICA1Cert        *x509.Certificate
	clientICA1CertByte    []byte
	clientICA1CertPrivKey *rsa.PrivateKey

	// client cert ICA2
	clientICA2Cert        *x509.Certificate
	clientICA2CertByte    []byte
	clientICA2CertPrivKey *rsa.PrivateKey
}

var testData *TestData

func testSetupCA(t *testing.T) {
	if testData != nil {
		return
	}

	//
	// Create a self signed CA
	//
	rootKey, err := cpkix.CreateRSAKey(1024)
	require.NoError(t, err)

	cpkixRootCrt, err := cpkix.CreateCertificateAuthorityWithOptions(rootKey, "Test", time.Now().AddDate(0, 0, 1), "Test Root", "US", "California", "San Francisco", "Test Root", nil, cpkix.WithPathlenOption(2, false))
	require.NoError(t, err)

	rootCert, err := cpkixRootCrt.GetRawCertificate()
	require.NoError(t, err)
	//t.Log(cpkixCrt.Export())
	//t.Log(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	printCert(t, rootCert)

	//
	// create an intermediate CA 1 to sign cert to be used by clients and server
	//
	intermediateCAKey1, err := cpkix.CreateRSAKey(1024)
	require.NoError(t, err)

	intermediateCACSR1, err := cpkix.CreateCertificateSigningRequest(intermediateCAKey1, "Test 1", nil, []string{"localhost"}, nil, "test", "US", "California", "San Fransciso", "Test Intermediate 1")
	require.NoError(t, err)

	cpkixIntermediateCrt1, err := cpkix.CreateIntermediateCertificateAuthorityWithOptions(cpkixRootCrt, rootKey, intermediateCACSR1, time.Now().AddDate(0, 0, 1), cpkix.WithPathlenOption(1, false))
	require.NoError(t, err)

	intermediateCert1, err := cpkixIntermediateCrt1.GetRawCertificate()
	require.NoError(t, err)
	printCert(t, intermediateCert1)

	//
	// create an intermediate CA 2 to sign cert to be used by clients and server
	//
	intermediateCAKey2, err := cpkix.CreateRSAKey(1024)
	require.NoError(t, err)

	intermediateCACSR2, err := cpkix.CreateCertificateSigningRequest(intermediateCAKey2, "Test 2", nil, []string{"localhost"}, nil, "test", "US", "California", "San Fransciso", "Test Intermediate 2")
	require.NoError(t, err)

	cpkixIntermediateCrt2, err := cpkix.CreateIntermediateCertificateAuthorityWithOptions(cpkixRootCrt, rootKey, intermediateCACSR2, time.Now().AddDate(0, 0, 1), cpkix.WithPathlenOption(1, false))
	require.NoError(t, err)

	intermediateCert2, err := cpkixIntermediateCrt2.GetRawCertificate()
	require.NoError(t, err)
	//t.Log(cpkixCrt.Export())
	//t.Log(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	printCert(t, intermediateCert2)

	scert, scertByte, scertPrivKey := GenCert(t, intermediateCert1, intermediateCAKey1.Private.(*rsa.PrivateKey), true)
	printCert(t, scert)

	ccert, ccertByte, ccertPrivKey := GenCert(t, intermediateCert1, intermediateCAKey1.Private.(*rsa.PrivateKey), false)
	printCert(t, ccert)

	ccert2, ccert2Byte, ccert2PrivKey := GenCert(t, intermediateCert2, intermediateCAKey2.Private.(*rsa.PrivateKey), false)
	printCert(t, ccert2)

	testData = &TestData{
		rootKey:  rootKey,
		rootCert: rootCert,

		intermediateCAKey1:  intermediateCAKey1,
		intermediateCACert1: intermediateCert1,

		intermediateCAKey2:  intermediateCAKey2,
		intermediateCACert2: intermediateCert2,

		serverICA1Cert:        scert,
		serverICA1CertByte:    scertByte,
		serverICA1CertPrivKey: scertPrivKey,

		clientICA1Cert:        ccert,
		clientICA1CertByte:    ccertByte,
		clientICA1CertPrivKey: ccertPrivKey,

		clientICA2Cert:        ccert2,
		clientICA2CertByte:    ccert2Byte,
		clientICA2CertPrivKey: ccert2PrivKey,
	}
}

func printCert(t *testing.T, cert *x509.Certificate) {
	if os.Getenv("TRACE") == "" {
		return
	}
	msg := "=============="
	msg += "\nCert Common Name     : " + cert.Subject.CommonName
	msg += "\nIssuer Common Name   : " + cert.Issuer.CommonName
	msg += "\nCert OU              : " + strings.Join(cert.Subject.OrganizationalUnit, ",")
	msg += "\nCert Common Name     : " + cert.Subject.CommonName
	msg += "\nPermittedDNSDomains  : " + strings.Join(cert.DNSNames, ",")
	msg += "\nPublickKey Type      : " + cert.PublicKeyAlgorithm.String()
	msg += "\nIsCA                 : " + strconv.FormatBool(cert.IsCA)
	msg += "\nMaxPathLen           : " + strconv.FormatInt(int64(cert.MaxPathLen), 10)
	t.Log(msg)
}

func GenCert(t *testing.T, ICACert *x509.Certificate, ICAKey *rsa.PrivateKey, serverCert bool) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	commonName := "client"
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	}

	if serverCert {
		commonName = "server"
		extKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		}
	}
	var certTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: ICACert.Subject.OrganizationalUnit,
			Organization:       ICACert.Subject.Organization,
			Locality:           ICACert.Subject.Locality,
			Country:            ICACert.Subject.Country,
		},
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(0, 0, 1),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    extKeyUsage,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}

	if serverCert {
		certTemplate.DNSNames = []string{"localhost"}
	}

	cert, certPEM := genCert(&certTemplate, ICACert, &priv.PublicKey, ICAKey)
	return cert, certPEM, priv

}

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}
