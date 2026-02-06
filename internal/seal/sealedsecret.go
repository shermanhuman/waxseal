package seal

import (
	"fmt"

	"github.com/shermanhuman/waxseal/internal/core"
	"sigs.k8s.io/yaml"
)

// SealedSecret represents a parsed SealedSecret manifest.
type SealedSecret struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ObjectMeta       `json:"metadata"`
	Spec       SealedSecretSpec `json:"spec"`
}

// ObjectMeta contains standard Kubernetes metadata.
type ObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// SealedSecretSpec contains the sealed secret specification.
type SealedSecretSpec struct {
	EncryptedData map[string]string   `json:"encryptedData,omitempty"`
	Template      *SecretTemplateSpec `json:"template,omitempty"`
}

// SecretTemplateSpec mirrors the target Secret structure.
type SecretTemplateSpec struct {
	Type     string            `json:"type,omitempty"`
	Metadata *ObjectMeta       `json:"metadata,omitempty"`
	Data     map[string]string `json:"data,omitempty"`
}

// Scope constants for SealedSecrets.
const (
	ScopeStrict        = "strict"
	ScopeNamespaceWide = "namespace-wide"
	ScopeClusterWide   = "cluster-wide"
)

// Annotation keys for SealedSecrets.
const (
	AnnotationScope     = "sealedsecrets.bitnami.com/scope"
	AnnotationNamespace = "sealedsecrets.bitnami.com/namespace"
	AnnotationName      = "sealedsecrets.bitnami.com/name"
)

// NewSealedSecret constructs a SealedSecret with the correct annotations.
// This is the single authoritative builder — all manifest creation goes through here.
func NewSealedSecret(name, namespace, scope, secretType string, encryptedData map[string]string) *SealedSecret {
	ss := &SealedSecret{
		APIVersion: "bitnami.com/v1alpha1",
		Kind:       "SealedSecret",
		Metadata: ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: SealedSecretSpec{
			EncryptedData: encryptedData,
		},
	}

	// Add scope annotation if not strict (strict is the default)
	if scope != ScopeStrict && scope != "" {
		ss.Metadata.Annotations = map[string]string{
			AnnotationScope: scope,
		}
	}

	// Add template with type if not Opaque
	if secretType != "" && secretType != "Opaque" {
		ss.Spec.Template = &SecretTemplateSpec{
			Type: secretType,
		}
	}

	return ss
}

// ParseSealedSecret parses a SealedSecret from YAML bytes.
func ParseSealedSecret(data []byte) (*SealedSecret, error) {
	var ss SealedSecret
	if err := yaml.Unmarshal(data, &ss); err != nil {
		return nil, core.WrapValidation("sealedsecret", err)
	}

	if ss.Kind != "SealedSecret" {
		return nil, core.NewValidationError("kind", fmt.Sprintf("expected 'SealedSecret', got %q", ss.Kind))
	}

	if ss.Metadata.Name == "" {
		return nil, core.NewValidationError("metadata.name", "required")
	}

	if ss.Metadata.Namespace == "" {
		return nil, core.NewValidationError("metadata.namespace", "required")
	}

	return &ss, nil
}

// GetScope returns the scope of the SealedSecret based on annotations.
// Returns "strict" if no scope annotation is present.
func (ss *SealedSecret) GetScope() string {
	if ss.Metadata.Annotations == nil {
		return ScopeStrict
	}

	scope := ss.Metadata.Annotations[AnnotationScope]
	switch scope {
	case ScopeNamespaceWide, ScopeClusterWide:
		return scope
	default:
		return ScopeStrict
	}
}

// GetEncryptedKeys returns the list of encrypted key names.
func (ss *SealedSecret) GetEncryptedKeys() []string {
	keys := make([]string, 0, len(ss.Spec.EncryptedData))
	for k := range ss.Spec.EncryptedData {
		keys = append(keys, k)
	}
	return keys
}

// GetSecretType returns the target Secret type.
// Returns "Opaque" if not specified.
func (ss *SealedSecret) GetSecretType() string {
	if ss.Spec.Template != nil && ss.Spec.Template.Type != "" {
		return ss.Spec.Template.Type
	}
	return "Opaque"
}

// ToYAML serializes the SealedSecret to YAML.
func (ss *SealedSecret) ToYAML() ([]byte, error) {
	return yaml.Marshal(ss)
}
