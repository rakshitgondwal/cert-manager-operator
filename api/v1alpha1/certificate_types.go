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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// +kubebuilder:validation:Required
	// DNS name for the certificate
	DNSName string `json:"dnsName"`
	// +kubebuilder:validation:Required
	// Validity period (e.g., "360d")
	Validity string `json:"validity"`
	// +kubebuilder:validation:Required
	// Reference to the Secret where the certificate is stored
	SecretRef SecretReference `json:"secretRef"`
}

// SecretReference refers to a Kubernetes Secret
type SecretReference struct {
	// +kubebuilder:validation:Required
	// Name of the Secret
	Name string `json:"name"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	// +optional
	// Current status of the Certificate
	CurrentStatus string `json:"currentStatus,omitempty"`
	// +optional
	// Human-readable message providing details about the current status
	Message string `json:"message,omitempty"`
	// +optional
	// Timestamp of the last status update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="CurrentStatus",type=string,JSONPath=`.status.currentStatus`
// +kubebuilder:printcolumn:name="LastUpdated",type=string,JSONPath=`.status.lastUpdated`

// Certificate is the Schema for the certificates API
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CertificateSpec `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
