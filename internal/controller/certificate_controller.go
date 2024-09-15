/*
Copyright 2024 rakshitgondwal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certsv1alpha1 "github.com/rakshitgondwal/cert-manager-operator.git/api/v1alpha1"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.core.rakshitgondwal.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.core.rakshitgondwal.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.core.rakshitgondwal.io,resources=certificates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Corrected log statement with proper key-value pairs
	logger.Info("Reconciling Certificate", "namespace", req.Namespace, "name", req.Name)

	var cert certsv1alpha1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to fetch Certificate")
		return ctrl.Result{}, err
	}

	validityDuration, err := time.ParseDuration(cert.Spec.Validity)
	if err != nil {
		logger.Error(err, "Invalid validity duration format")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	err = r.Get(ctx, client.ObjectKey{Name: cert.Spec.SecretRef.Name, Namespace: req.Namespace}, &secret)
	if err != nil && errors.IsNotFound(err) {
		certPEM, keyPEM, err := generateSelfSignedCert(cert.Spec.DNSName, validityDuration)
		if err != nil {
			logger.Error(err, "Failed to generate certificate")
			return ctrl.Result{}, err
		}

		logger.Info("Creating new Secret")
		newSecret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cert.Spec.SecretRef.Name,
				Namespace: req.Namespace,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
		}

		if err := r.Create(ctx, &newSecret); err != nil {
			logger.Error(err, "Failed to create Secret")
			return ctrl.Result{}, err
		}

		logger.Info("Successfully created Secret with TLS certificate")
		return ctrl.Result{}, nil
	} else if err != nil {
		logger.Error(err, "Failed to get Secret", "Secret.Name")
		return ctrl.Result{}, err
	}

	logger.Info("Secret already exists")
	certPEM, exists := secret.Data["tls.crt"]
	if !exists {
		logger.Error(fmt.Errorf("tls.crt not found in Secret"), "Secret data incomplete")
		return ctrl.Result{}, nil
	}

	parsedCert, err := parseCertificate(certPEM)
	if err != nil {
		logger.Error(err, "Failed to parse existing certificate")
		return ctrl.Result{}, nil
	}

	timeLeft := time.Until(parsedCert.NotAfter)
	renewalThresholdDuration := 30 * 24 * time.Hour

	if timeLeft < renewalThresholdDuration {
		logger.Info("Certificate is nearing expiration. Initiating renewal.")

		newCertPEM, newKeyPEM, err := generateSelfSignedCert(cert.Spec.DNSName, validityDuration)
		if err != nil {
			logger.Error(err, "Failed to generate renewed certificate")
			return ctrl.Result{}, err
		}

		secret.Data["tls.crt"] = newCertPEM
		secret.Data["tls.key"] = newKeyPEM

		if err := r.Update(ctx, &secret); err != nil {
			logger.Error(err, "Failed to update Secret with renewed certificate")
			return ctrl.Result{}, err
		}

		logger.Info("Successfully renewed TLS certificate")
	} else {
		logger.Info("Certificate is still valid. No renewal needed.")
	}

	return ctrl.Result{}, nil
}

func generateSelfSignedCert(dnsName string, validity time.Duration) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"rakshitgondwal.io"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM, nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1alpha1.Certificate{}).
		Complete(r)
}
