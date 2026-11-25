{{- define "grdr-node-sensor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "grdr-node-sensor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "grdr-node-sensor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "grdr-node-sensor.labels" -}}
helm.sh/chart: {{ include "grdr-node-sensor.chart" . }}
{{ include "grdr-node-sensor.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- define "grdr-node-sensor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grdr-node-sensor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "grdr-node-sensor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "grdr-node-sensor.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "grdr-node-sensor.image" -}}
{{- $zero := "sha256:0000000000000000000000000000000000000000000000000000000000000000" -}}
{{- if or (not .Values.image.digest) (eq .Values.image.digest $zero) -}}
{{- fail "grdr-node-sensor image.digest must be a valid non-zero sha256 digest (D-59)" -}}
{{- end -}}
{{- printf "%s/%s@%s" (.Values.global.imageRegistry | trimSuffix "/") .Values.image.repository .Values.image.digest -}}
{{- end -}}

{{- define "grdr-node-sensor.validate" -}}
{{- $badCidr := "^(?:0\\.0\\.0\\.0/[0-7]$|128\\.0\\.0\\.0/1$|169\\.254\\.|::/[0-7]$|[fF][eE][89aAbB][0-9a-fA-F]:)" -}}
{{- if and .Values.sidecar.enabled .Values.sidecar.mutatingWebhook.enabled (not .Values.sidecar.mutatingWebhook.caBundle) (not .Values.sidecar.mutatingWebhook.certManagerInjectCAFrom) -}}
{{- fail "sidecar.mutatingWebhook requires either caBundle or certManagerInjectCAFrom when enabled" -}}
{{- end -}}
{{- range .Values.networkPolicy.allowEgressCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "networkPolicy.allowEgressCidrs cannot contain empty, wildcard, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.serverNamespace) (not .Values.networkPolicy.allowEgressCidrs) -}}
{{- fail "networkPolicy requires non-empty serverNamespace or allowEgressCidrs when enabled" -}}
{{- end -}}
{{- end -}}
