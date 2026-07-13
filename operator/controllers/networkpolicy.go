package controllers

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	agentwallv1alpha1 "github.com/noviqtechnologies/agentwall/operator/api/v1alpha1"
)

// Convention labels and defaults used by generated NetworkPolicies.
//
// FR-5 §5.5.8: "NetworkPolicy restricts all agent pod egress on MCP ports to
// gateway only. K8s Operator automatically applies NetworkPolicy during
// sidecar injection."
//
// We use label conventions rather than hard-coded pod names so operators can
// scale gateway replicas without re-writing the policy.
const (
	// DefaultMCPPort is the TCP port the gateway listens on.
	DefaultMCPPort int32 = 8080

	// DNSPort is required for cluster DNS resolution. Without this, agents
	// cannot even resolve the gateway's Service DNS name.
	DNSPort int32 = 53

	// DefaultAgentLabelKey is the label agent pods use to opt into
	// egress restriction. Combined with DefaultAgentLabelValue, this
	// forms the default AgentPodSelector.
	DefaultAgentLabelKey   = "agentwall.io/agent"
	DefaultAgentLabelValue = "true"

	// DefaultGatewayLabelKey is the label the gateway pod carries.
	DefaultGatewayLabelKey   = "agentwall.io/gateway"
	DefaultGatewayLabelValue = "true"

	// NetworkPolicyNameSuffix is appended to the AgentWallPolicy name to
	// derive the NetworkPolicy name. Keeping this deterministic makes
	// reconciliation lookups trivial.
	NetworkPolicyNameSuffix = "-agentwall-egress"

	// ManagedByLabelKey identifies resources owned by the operator.
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "agentwall-operator"

	// PolicyRefLabelKey links a generated resource back to its AgentWallPolicy.
	PolicyRefLabelKey = "agentwall.io/policy"
)

// networkPolicyName returns the deterministic name of the NetworkPolicy
// generated for a given AgentWallPolicy.
func networkPolicyName(policyName string) string {
	return policyName + NetworkPolicyNameSuffix
}

// buildNetworkPolicy constructs the desired NetworkPolicy for a given
// AgentWallPolicy. The output is DENY-BY-DEFAULT for egress with two
// explicit allow rules:
//
//  1. Egress to gateway pods on the MCP port (TCP)
//  2. Egress to DNS (53/tcp + 53/udp) — required for the agent to
//     resolve the gateway's Service name at all.
//
// Missing/empty fields on the CR fall back to the convention defaults
// declared above. Callers still need to set the owner reference via
// controller-runtime's SetControllerReference so garbage collection
// works when the parent CR is deleted.
func buildNetworkPolicy(policy *agentwallv1alpha1.AgentWallPolicy) *networkingv1.NetworkPolicy {
	agentSelector := policy.Spec.NetworkPolicy.AgentPodSelector
	if len(agentSelector) == 0 {
		agentSelector = map[string]string{DefaultAgentLabelKey: DefaultAgentLabelValue}
	}

	gatewaySelector := policy.Spec.NetworkPolicy.GatewayPodSelector
	if len(gatewaySelector) == 0 {
		gatewaySelector = map[string]string{DefaultGatewayLabelKey: DefaultGatewayLabelValue}
	}

	mcpPort := policy.Spec.NetworkPolicy.MCPPort
	if mcpPort == 0 {
		mcpPort = DefaultMCPPort
	}

	// intstr and Protocol values must be addressable — the NetworkPolicyPort
	// struct takes pointers so callers can leave fields nil to mean "any".
	mcpPortIS := intstr.FromInt(int(mcpPort))
	dnsPortIS := intstr.FromInt(int(DNSPort))
	tcpProto := corev1.ProtocolTCP
	udpProto := corev1.ProtocolUDP

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkPolicyName(policy.Name),
			Namespace: policy.Namespace,
			Labels: map[string]string{
				ManagedByLabelKey: ManagedByLabelValue,
				PolicyRefLabelKey: policy.Name,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Applied TO these pods (agents).
			PodSelector: metav1.LabelSelector{
				MatchLabels: agentSelector,
			},
			// We only restrict egress; ingress to agents is out of scope
			// for FR-5 §5.5.8 (that's the gateway's job).
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				// Rule 1: Agents may reach the gateway on the MCP port.
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: gatewaySelector,
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &tcpProto, Port: &mcpPortIS},
					},
				},
				// Rule 2: DNS. Without this rule the agent cannot resolve
				// the gateway's Service name and the whole thing is dead
				// on arrival. We allow to any pod because kube-dns lives
				// in kube-system and its selector is cluster-specific.
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &udpProto, Port: &dnsPortIS},
						{Protocol: &tcpProto, Port: &dnsPortIS},
					},
				},
			},
		},
	}
}
