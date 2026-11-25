{{- define "grdr-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "grdr-server.fullname" -}}
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

{{- define "grdr-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "grdr-server.labels" -}}
helm.sh/chart: {{ include "grdr-server.chart" . }}
{{ include "grdr-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- define "grdr-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grdr-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "grdr-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "grdr-server.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "grdr-server.image" -}}
{{- $zero := "sha256:0000000000000000000000000000000000000000000000000000000000000000" -}}
{{- if or (not .Values.image.digest) (eq .Values.image.digest $zero) -}}
{{- fail "grdr-server image.digest must be a valid non-zero sha256 digest (D-59)" -}}
{{- end -}}
{{- printf "%s/%s@%s" (.Values.global.imageRegistry | trimSuffix "/") .Values.image.repository .Values.image.digest -}}
{{- end -}}

{{- define "grdr-server.pkcs11Image" -}}
{{- $zero := "sha256:0000000000000000000000000000000000000000000000000000000000000000" -}}
{{- if or (not .Values.pkcs11Sidecar.image.digest) (eq .Values.pkcs11Sidecar.image.digest $zero) -}}
{{- fail "grdr-server pkcs11Sidecar.image.digest must be a valid non-zero sha256 digest" -}}
{{- end -}}
{{- printf "%s/%s@%s" (.Values.global.imageRegistry | trimSuffix "/") .Values.pkcs11Sidecar.image.repository .Values.pkcs11Sidecar.image.digest -}}
{{- end -}}

{{- define "grdr-server.validate" -}}
{{- $badCidr := "^(?:0\\.0\\.0\\.0/[0-7]$|128\\.0\\.0\\.0/1$|169\\.254\\.|::/[0-7]$|[fF][eE][89aAbB][0-9a-fA-F]:)" -}}
{{- range .Values.extraEnv -}}
{{- if not (regexMatch "^(RUST_LOG|RUST_BACKTRACE|OTEL_[A-Z0-9_]+)$" .name) -}}
{{- fail (printf "extraEnv allows only RUST_LOG, RUST_BACKTRACE, or OTEL_*; got %s" .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.networkPolicy.allowEgressCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "networkPolicy.allowEgressCidrs cannot contain empty, wildcard, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- range .Values.operator.ingress.allowCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "operator.ingress.allowCidrs cannot contain empty, wildcard, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.host must be set when ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.ingress.tls.enabled (not .Values.ingress.tls.secretName) -}}
{{- fail "ingress.tls.secretName must be set when ingress.tls.enabled is true" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled (not .Values.operator.ingress.host) -}}
{{- fail "operator.ingress.host must be set when operator.ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled .Values.operator.ingress.tls.enabled (not .Values.operator.ingress.tls.secretName) -}}
{{- fail "operator.ingress.tls.secretName must be set when operator.ingress.tls.enabled is true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.operator.enabled .Values.operator.ingress.enabled (eq .Values.ingress.host .Values.operator.ingress.host) -}}
{{- fail "D-70 violation: operator.ingress.host must be distinct from ingress.host" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled (not .Values.operator.ingress.allowCidrs) -}}
{{- fail "operator.ingress.allowCidrs must not be empty when operator.ingress.enabled is true" -}}
{{- end -}}
{{- end -}}
