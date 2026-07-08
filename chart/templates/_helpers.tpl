{{/*
Expand the name of the chart.
*/}}
{{- define "agentwall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name (truncated at 63 chars).
*/}}
{{- define "agentwall.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "agentwall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource in the chart.
*/}}
{{- define "agentwall.labels" -}}
helm.sh/chart: {{ include "agentwall.chart" . }}
{{ include "agentwall.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentwall
{{- end }}

{{/*
Selector labels (subset of common labels that must not change on upgrade).
*/}}
{{- define "agentwall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentwall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Operator-specific selector labels.
*/}}
{{- define "agentwall.operatorSelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentwall.name" . }}-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Gateway-specific selector labels. These are ALSO applied to the pod as
`agentwall.io/gateway: "true"` so the NetworkPolicy default selector matches.
*/}}
{{- define "agentwall.gatewaySelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentwall.name" . }}-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Service account name for the operator.
*/}}
{{- define "agentwall.operatorServiceAccountName" -}}
{{- printf "%s-operator" (include "agentwall.fullname" .) }}
{{- end }}

{{/*
Container image reference — falls back to Chart.AppVersion when tag is empty.
*/}}
{{- define "agentwall.operatorImage" -}}
{{- $tag := .Values.operator.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.operator.image.repository $tag -}}
{{- end }}

{{- define "agentwall.gatewayImage" -}}
{{- $tag := .Values.gateway.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.gateway.image.repository $tag -}}
{{- end }}

{{/*
Resolve the ConfigMap name that holds the gateway policy — either the
external one the user pointed at, or the chart-managed one.
*/}}
{{- define "agentwall.policyConfigMapName" -}}
{{- if .Values.gateway.policy.externalConfigMap -}}
{{- .Values.gateway.policy.externalConfigMap -}}
{{- else -}}
{{- printf "%s-gateway-policy" (include "agentwall.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Resolve the TLS Secret name — either user-provided or chart-generated.
*/}}
{{- define "agentwall.tlsSecretName" -}}
{{- if .Values.gateway.tls.secretName -}}
{{- .Values.gateway.tls.secretName -}}
{{- else -}}
{{- printf "%s-gateway-tls" (include "agentwall.fullname" .) -}}
{{- end -}}
{{- end }}
