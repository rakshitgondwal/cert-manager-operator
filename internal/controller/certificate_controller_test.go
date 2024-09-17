package controller

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	tests := []struct {
		name       string
		dnsName    string
		validity   string
		expectErr  bool
		verifyFunc func(t *testing.T, certPEM, keyPEM []byte, err error)
	}{
		{
			name:      "standard validity",
			dnsName:   "example.com",
			validity:  "1y",
			expectErr: false,
			verifyFunc: func(t *testing.T, certPEM, keyPEM []byte, err error) {
				assert.NoError(t, err, "Expected no error for valid input")

				block, _ := pem.Decode(certPEM)
				assert.NotNil(t, block, "Failed to decode certificate PEM")
				assert.Equal(t, "CERTIFICATE", block.Type, "Incorrect certificate PEM type")

				cert, err := x509.ParseCertificate(block.Bytes)
				assert.NoError(t, err, "Failed to parse certificate")
				assert.Contains(t, cert.DNSNames, "example.com", "DNSNames does not contain the expected DNS name")
				assert.WithinDuration(t, time.Now().Add(365*24*time.Hour), cert.NotAfter, time.Minute, "Certificate NotAfter is incorrect")

				block, _ = pem.Decode(keyPEM)
				assert.NotNil(t, block, "Failed to decode key PEM")
				assert.Equal(t, "RSA PRIVATE KEY", block.Type, "Incorrect key PEM type")
			},
		},
		{
			name:      "short validity",
			dnsName:   "short-validity.com",
			validity:  "1h",
			expectErr: false,
			verifyFunc: func(t *testing.T, certPEM, keyPEM []byte, err error) {
				assert.NoError(t, err, "Expected no error for short validity input")

				block, _ := pem.Decode(certPEM)
				assert.NotNil(t, block, "Failed to decode certificate PEM")
				assert.Equal(t, "CERTIFICATE", block.Type, "Incorrect certificate PEM type")

				cert, err := x509.ParseCertificate(block.Bytes)
				assert.NoError(t, err, "Failed to parse certificate")
				assert.Contains(t, cert.DNSNames, "short-validity.com", "DNSNames does not contain the expected DNS name")
				assert.WithinDuration(t, time.Now().Add(1*time.Hour), cert.NotAfter, time.Minute, "Certificate NotAfter is incorrect")

				block, _ = pem.Decode(keyPEM)
				assert.NotNil(t, block, "Failed to decode key PEM")
				assert.Equal(t, "RSA PRIVATE KEY", block.Type, "Incorrect key PEM type")
			},
		},
		{
			name:      "zero validity",
			dnsName:   "zero-validity.com",
			validity:  "0h",
			expectErr: false,
			verifyFunc: func(t *testing.T, certPEM, keyPEM []byte, err error) {
				assert.NoError(t, err, "Expected no error for zero validity input")

				block, _ := pem.Decode(certPEM)
				assert.NotNil(t, block, "Failed to decode certificate PEM")
				assert.Equal(t, "CERTIFICATE", block.Type, "Incorrect certificate PEM type")

				cert, err := x509.ParseCertificate(block.Bytes)
				assert.NoError(t, err, "Failed to parse certificate")
				assert.Contains(t, cert.DNSNames, "zero-validity.com", "DNSNames does not contain the expected DNS name")
				assert.WithinDuration(t, time.Now(), cert.NotAfter, time.Second, "Certificate NotAfter should be equal to NotBefore")

				block, _ = pem.Decode(keyPEM)
				assert.NotNil(t, block, "Failed to decode key PEM")
				assert.Equal(t, "RSA PRIVATE KEY", block.Type, "Incorrect key PEM type")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dur, err := parseCustomDuration(tt.validity)
			assert.Nil(t, err)
			certPEM, keyPEM, err := generateSelfSignedCert(tt.dnsName, dur)
			tt.verifyFunc(t, certPEM, keyPEM, err)
		})
	}
}

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		expectCert *x509.Certificate
		expectErr  bool
	}{
		{
			name:       "Valid certificate PEM",
			input:      mustGenerateCert(t, "valid-cert.com", 365*24*time.Hour),
			expectCert: nil,
			expectErr:  false,
		},
		{
			name:       "Invalid PEM data",
			input:      []byte("-----BEGIN CERTIFICATE-----\nInvalidData\n-----END CERTIFICATE-----"),
			expectCert: nil,
			expectErr:  true,
		},
		{
			name:       "Wrong PEM block type",
			input:      []byte("-----BEGIN RSA PRIVATE KEY-----\nInvalidData\n-----END RSA PRIVATE KEY-----"),
			expectCert: nil,
			expectErr:  true,
		},
		{
			name:       "Empty PEM data",
			input:      []byte(""),
			expectCert: nil,
			expectErr:  true,
		},
		{
			name:       "Partial PEM data",
			input:      []byte("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOC\n-----END CERTIFICATE-----"),
			expectCert: nil,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificate(tt.input)
			if tt.expectErr {
				assert.Error(t, err, "Expected an error for invalid input")
			} else {
				assert.NoError(t, err, "Did not expect an error for valid input")
				if cert != nil {
					assert.Contains(t, cert.DNSNames, "valid-cert.com", "Certificate DNSNames should contain 'valid-cert.com'")
					assert.True(t, cert.NotAfter.After(time.Now()), "Certificate should be valid in the future")
				}
			}
		})
	}
}

func mustGenerateCert(t *testing.T, dnsName string, validity time.Duration) []byte {
	cert, _, err := generateSelfSignedCert(dnsName, validity)
	assert.NoError(t, err, "Failed to generate test certificate")
	return cert
}

func TestParseCustomDuration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  time.Duration
		expectErr bool
	}{
		{
			name:      "Valid seconds",
			input:     "30s",
			expected:  30 * time.Second,
			expectErr: false,
		},
		{
			name:      "Valid minutes",
			input:     "15m",
			expected:  15 * time.Minute,
			expectErr: false,
		},
		{
			name:      "Valid hours",
			input:     "5h",
			expected:  5 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Valid days",
			input:     "365d",
			expected:  365 * 24 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Valid weeks",
			input:     "2w",
			expected:  14 * 24 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Valid years",
			input:     "1y",
			expected:  365 * 24 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Invalid unit",
			input:     "10x",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Missing unit",
			input:     "100",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Non-numeric value",
			input:     "abc",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Empty string",
			input:     "",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Negative duration",
			input:     "-5h",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Zero duration",
			input:     "0s",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "Multiple units (unsupported)",
			input:     "1w2d",
			expected:  0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration, err := parseCustomDuration(tt.input)
			if tt.expectErr {
				assert.Error(t, err, "Expected an error for input: %s", tt.input)
			} else {
				assert.NoError(t, err, "Did not expect an error for input: %s", tt.input)
				assert.Equal(t, tt.expected, duration, "Duration mismatch for input: %s", tt.input)
			}
		})
	}
}
