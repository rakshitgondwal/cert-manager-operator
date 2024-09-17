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
	"regexp"
	"strconv"
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

	logger.Info("Reconciling Certificate", "namespace", req.Namespace, "name", req.Name)

	// look for the certificate resource if it exists or not
	var cert certsv1alpha1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to fetch Certificate")
		return ctrl.Result{}, err
	}

	// set the status fields incase they are nto defined
	if cert.Status.CurrentStatus == "" && cert.Status.Message == "" {
		cert.Status = certsv1alpha1.CertificateStatus{}
	}

	// check if the value spec.validity is valid or not
	// this will also convert the validity value in form of hours
	validityDuration, err := parseCustomDuration(cert.Spec.Validity)
	if err != nil {
		logger.Error(err, "Unable to parse validity duration")
		if err := r.updateCertificateStatus(ctx, &cert, "InvalidDuration", err.Error()); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
		return ctrl.Result{}, nil
	}

	// look for the secret refrenced inside the cluster
	// if exists, check for the expiration value of the certificate, if it is < 30 days, renew the cert
	// if not exists, create a new secret with a new cert
	var secret corev1.Secret
	err = r.Get(ctx, client.ObjectKey{Name: cert.Spec.SecretRef.Name, Namespace: req.Namespace}, &secret)
	if err != nil && errors.IsNotFound(err) {
		// create a new cert
		certPEM, keyPEM, err := generateSelfSignedCert(cert.Spec.DNSName, validityDuration)
		if err != nil {
			logger.Error(err, "Failed to generate certificate")
			if err := r.updateCertificateStatus(ctx, &cert, "CertGenerationFailed", err.Error()); err != nil {
				logger.Error(err, "Error updating Certificate status")
			}
			return ctrl.Result{}, err
		}

		// create a new secret
		logger.Info("Creating new Secret")
		newSecret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cert.Spec.SecretRef.Name,
				Namespace: req.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(&cert, certsv1alpha1.GroupVersion.WithKind("Certificate")),
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
		}

		if err := r.Create(ctx, &newSecret); err != nil {
			logger.Error(err, "Failed to create Secret")
			if err := r.updateCertificateStatus(ctx, &cert, "SecretCreationFailed", err.Error()); err != nil {
				logger.Error(err, "Error updating Certificate status")
			}
			return ctrl.Result{}, err
		}

		logger.Info("Successfully created Secret with TLS certificate")
		if err := r.updateCertificateStatus(ctx, &cert, "CertificateCreated", "TLS certificate successfully created"); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}

		return ctrl.Result{}, nil
	} else if err != nil {
		// log if there was any other error
		logger.Error(err, "Failed to get Secret", "Secret.Name")
		if err := r.updateCertificateStatus(ctx, &cert, "SecretFetchFailed", err.Error()); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
		return ctrl.Result{}, err
	}

	// since there was no error, that means secret already exists
	logger.Info("Secret already exists")
	// parse the cert to check the expiration date
	certPEM, exists := secret.Data["tls.crt"]
	if !exists {
		errMsg := "tls.crt not found in Secret"
		logger.Error(fmt.Errorf(errMsg), "Secret data incomplete")
		if err := r.updateCertificateStatus(ctx, &cert, "MissingCertData", errMsg); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
		return ctrl.Result{}, nil
	}

	parsedCert, err := parseCertificate(certPEM)
	if err != nil {
		logger.Error(err, "Failed to parse existing certificate")
		if err := r.updateCertificateStatus(ctx, &cert, "CertParseFailed", err.Error()); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
		return ctrl.Result{}, nil
	}

	// check for the expiration date
	timeLeft := time.Until(parsedCert.NotAfter)
	renewalThresholdDuration := 30 * 24 * time.Hour

	// if the expiration date is less than 30 days, renew the cert
	if timeLeft < renewalThresholdDuration {
		logger.Info("Certificate is nearing expiration. Initiating renewal.")

		newCertPEM, newKeyPEM, err := generateSelfSignedCert(cert.Spec.DNSName, validityDuration)
		if err != nil {
			logger.Error(err, "Failed to generate renewed certificate")
			if err := r.updateCertificateStatus(ctx, &cert, "CertRenewalFailed", err.Error()); err != nil {
				logger.Error(err, "Error updating Certificate status")
			}
			return ctrl.Result{}, err
		}

		secret.Data["tls.crt"] = newCertPEM
		secret.Data["tls.key"] = newKeyPEM

		if err := r.Update(ctx, &secret); err != nil {
			logger.Error(err, "Failed to update Secret with renewed certificate")
			if err := r.updateCertificateStatus(ctx, &cert, "SecretUpdateFailed", err.Error()); err != nil {
				logger.Error(err, "Error updating Certificate status")
			}
			return ctrl.Result{}, err
		}

		logger.Info("Successfully renewed TLS certificate")
		if err := r.updateCertificateStatus(ctx, &cert, "CertificateRenewed", "TLS certificate successfully renewed"); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
	} else {
		// there is time for the cert to be renewed, thus we don't perform any action and return
		logger.Info("Certificate is still valid. No renewal needed.")
		if err := r.updateCertificateStatus(ctx, &cert, "CertificateValid", "TLS certificate is still valid"); err != nil {
			logger.Error(err, "Error updating Certificate status")
		}
	}

	return ctrl.Result{}, nil
}

// used to update the certificate status field
func (r *CertificateReconciler) updateCertificateStatus(ctx context.Context, cert *certsv1alpha1.Certificate, status, message string) error {
	cert.Status.CurrentStatus = status
	cert.Status.Message = message
	cert.Status.LastUpdated = metav1.Now()

	if err := r.Status().Update(ctx, cert); err != nil {
		return fmt.Errorf("Failed to update Certificate status")
	}
	return nil
}

// used to generate a new self signed certificate
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

// used to parse the certificate
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

// used to verify and parse the spec.interval field
func parseCustomDuration(s string) (time.Duration, error) {
	re := regexp.MustCompile(`^(\d+)([smhdwy])$`)
	matches := re.FindStringSubmatch(s)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value in duration: %v", err)
	}

	var duration time.Duration
	switch matches[2] {
	case "s":
		duration = time.Duration(value) * time.Second
	case "m":
		duration = time.Duration(value) * time.Minute
	case "h":
		duration = time.Duration(value) * time.Hour
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	case "w":
		duration = time.Duration(value) * 7 * 24 * time.Hour
	case "y":
		duration = time.Duration(value) * 365 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("unknown duration unit: %s", matches[2])
	}

	return duration, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1alpha1.Certificate{}).
		Complete(r)
}
