# AgentWall Helm Chart

Deploys the [VEXA AgentWall](https://github.com/noviqtechnologies/agentwall)
security gateway and its Kubernetes operator into a cluster.

## What this chart installs

| Component | Purpose |
|-----------|---------|
| `AgentWallPolicy` CRD | Custom resource definition (optional, on by default) |
| `agentwall-operator` Deployment | Reconciles `AgentWallPolicy` → ConfigMap + NetworkPolicy |
| `agentwall-gateway` Deployment | The enforcement proxy (FR-5 §5.5) |
| `agentwall-gateway` Service | ClusterIP fronting the gateway pods |
| Gateway policy ConfigMap | The active policy (mounted into the gateway) |
| Gateway TLS Secret | Optional; DEV self-signed or user-provided |
| Sample `AgentWallPolicy` CR | Optional, off by default |

## Prerequisites

- Kubernetes **1.24+**
- Helm **3.10+**
- Cluster CNI that honors `NetworkPolicy` (Calico, Cilium, Antrea, etc.) if
  you plan to use `networkPolicy.enforced: true`

## Install

```bash
# Add the local chart directory
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace
```

For production, pin your images explicitly:

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set operator.image.repository=myregistry.example.com/agentwall-operator \
  --set operator.image.tag=v1.0.13 \
  --set gateway.image.repository=myregistry.example.com/agentwall \
  --set gateway.image.tag=v1.0.13 \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls
```

## Common patterns

### Enable TLS with your own cert

```bash
# Create the Secret first
kubectl create secret tls my-gateway-tls \
  --cert=cert.pem --key=key.pem \
  -n agentwall-system

helm upgrade agentwall ./chart \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls
```

### Enable TLS with a self-signed cert (DEV ONLY)

```bash
helm upgrade agentwall ./chart \
  --set gateway.tls.enabled=true \
  --set gateway.tls.createSelfSigned=true
```

### Enable NetworkPolicy enforcement

Label your agent pods with `agentwall.io/agent=true`, then create an
`AgentWallPolicy` CR (or edit `values.yaml`) with:

```yaml
policy:
  create: true
  networkPolicyEnforced: true
```

The operator will generate a NetworkPolicy that restricts those pods'
egress to the gateway on the MCP port (+DNS).

### Point at an externally-managed policy ConfigMap

```yaml
gateway:
  policy:
    externalConfigMap: my-team-policy-config
    # inline: is ignored when externalConfigMap is set
```

### Trigger policy hot-reload (FR-5 AC-5.6)

Two options:

```bash
# Option A: HTTP endpoint
kubectl exec -n agentwall-system deploy/agentwall-gateway -- \
  wget -qO- --post-data '' http://localhost:8080/reload

# Option B: SIGHUP
POD=$(kubectl get pod -n agentwall-system -l app.kubernetes.io/component=gateway -o name | head -1)
kubectl exec -n agentwall-system $POD -- kill -HUP 1
```

## Upgrade

```bash
helm upgrade agentwall ./chart -n agentwall-system
```

Rolling upgrades preserve request continuity as long as `gateway.replicas >= 2`.
The gateway pod's `preStop` hook waits 5s before SIGTERM so in-flight requests
have time to drain.

## Uninstall

```bash
helm uninstall agentwall -n agentwall-system

# CRDs are kept intentionally (helm.sh/resource-policy: keep) so existing
# AgentWallPolicy CRs are not garbage-collected on uninstall. Remove them
# explicitly if you really want them gone:
kubectl delete crd agentwallpolicies.agentwall.io
```

## Values reference

See [values.yaml](values.yaml) — every value has an inline comment explaining
what it does and why the default is what it is. The most commonly touched
sections are marked `COMMON`.

## FR-5 compliance summary

| PRD requirement | Chart mapping |
|-----------------|--------------|
| §5.5.3 Deployable via Helm chart | This chart |
| §5.5.4 Fail-closed on crash | Gateway binary (panic hook + JoinSet abort) |
| §5.5.6 TLS on listener | `gateway.tls.enabled=true` + Secret with tls.crt/tls.key |
| §5.5.8 NetworkPolicy | `AgentWallPolicy.spec.networkPolicy.enforced=true` |
| AC-5.6 Hot-reload | `POST /reload` HTTP or SIGHUP to PID 1 |
