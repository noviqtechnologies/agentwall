package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityConfig defines identity parameters
type IdentityConfig struct {
	Provider  string `json:"provider,omitempty"`
	VaultAddr string `json:"vaultAddr,omitempty"`
}

// NetworkPolicyConfig defines network policy configuration
type NetworkPolicyConfig struct {
	Enforced bool `json:"enforced,omitempty"`
}

// AgentWallPolicySpec defines the desired state of AgentWallPolicy
type AgentWallPolicySpec struct {
	// GatewayImage defines the AgentWall image to inject
	GatewayImage string `json:"gatewayImage,omitempty"`
	
	// Policy contains the inline YAML policy definition
	Policy string `json:"policy,omitempty"`
	
	// Identity configuration
	Identity IdentityConfig `json:"identity,omitempty"`

	// NetworkPolicy configuration
	NetworkPolicy NetworkPolicyConfig `json:"networkPolicy,omitempty"`
}

// AgentWallPolicyStatus defines the observed state of AgentWallPolicy
type AgentWallPolicyStatus struct {
	// Phase is the current state of the policy
	Phase string `json:"phase,omitempty"`
	
	// GatewayPodName is the name of the deployed gateway pod
	GatewayPodName string `json:"gatewayPodName,omitempty"`
	
	// LastReconcileTime is the last time the policy was reconciled
	LastReconcileTime string `json:"lastReconcileTime,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AgentWallPolicy is the Schema for the agentwallpolicies API
type AgentWallPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentWallPolicySpec   `json:"spec,omitempty"`
	Status AgentWallPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AgentWallPolicyList contains a list of AgentWallPolicy
type AgentWallPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentWallPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AgentWallPolicy{}, &AgentWallPolicyList{})
}
