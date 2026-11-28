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
{{- $badCidr := "^(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[01]$|0\\.|127\\.|(?:[0-9]|[1-9][0-9]|1[0-8][0-9]|19[01])\\.[^/]+/[0-7]$|169\\.(?:254\\.|[^/]+/[0-8]$|(?:1[2-9][0-9]|2[0-4][0-9]|25[0-5])\\.[^/]+/(?:9|1[0-5])$)|[0-9A-Fa-f:]+/[0-7]$|(?:0+:)+:(?:0+:)*0*/|::(?:0+:)*0*/|(?:0+:){1,7}0+/|(?:::(?:0+:)*|(?:0+:){1,7}:?(?:0+:)*)0*1/|(?:(?:0+:)+:(?:0+:)*|::(?:0+:)*|(?:0+:){5})(?:[^/]*/(?:[0-7]?[0-9]|80)$|[89a-fA-F][0-9a-fA-F]{3}:[^/]+/81$|[c-fC-F][0-9a-fA-F]{3}:[^/]+/82$|[eEfF][0-9a-fA-F]{3}:[^/]+/83$|[fF][0-9a-fA-F]{3}:[^/]+/84$|[fF][89a-fA-F][0-9a-fA-F]{2}:[^/]+/85$|[fF][c-fC-F][0-9a-fA-F]{2}:[^/]+/86$|[fF][eEfF][0-9a-fA-F]{2}:[^/]+/87$|[fF]{2}[0-9a-fA-F]{2}:[^/]+/88$|[fF]{2}[89a-fA-F][0-9a-fA-F]:[^/]+/89$|[fF]{2}[c-fC-F][0-9a-fA-F]:[^/]+/90$|[fF]{2}[eEfF][0-9a-fA-F]:[^/]+/91$|[fF]{3}[0-9a-fA-F]:[^/]+/92$|[fF]{3}[89a-fA-F]:[^/]+/93$|[fF]{3}[c-fC-F]:[^/]+/94$|[fF]{3}[eEfF]:[^/]+/95$|[fF]{4}:)|[fF][dD][0-9a-fA-F]{2}:[^/]+/8$|[fF][dD][0-7][0-9a-fA-F]:[^/]+/(?:9|1[0-5])$|[fF][dD]00:[^/]+/16$|[fF][dD]00:(?:[0-7][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/17$|[fF][dD]00:(?:[0-3][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/18$|[fF][dD]00:(?:[01][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/19$|[fF][dD]00:(?:0[0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/20$|[fF][dD]00:0*[89a-fA-F][0-9a-fA-F]{2}:[^/]+/21$|[fF][dD]00:0*[c-fC-F][0-9a-fA-F]{2}:[^/]+/22$|[fF][dD]00:0*[eEfF][0-9a-fA-F]{2}:[^/]+/23$|[fF][dD]00:0*[eE][0-9a-fA-F]{2}:[^/]+/24$|[fF][dD]00:0*[eE][89a-fA-F][0-9a-fA-F]:[^/]+/25$|[fF][dD]00:0*[eE][c-fC-F][0-9a-fA-F]:[^/]+/26$|[fF][dD]00:0*[eE][cCdD][0-9a-fA-F]:[^/]+/27$|[fF][dD]00:0*[eE][cC][0-9a-fA-F]:[^/]+/28$|[fF][dD]00:0*[eE][cC][0-7]:[^/]+/29$|[fF][dD]00:0*[eE][cC][0-3]:[^/]+/30$|[fF][dD]00:0*[eE][cC][23]:[^/]+/31$|[fF][dD]00:0*[eE][cC]2[:/]|[fF][eE][0-9a-fA-F]{2}:[^/]+/8$|[fF][eE][89aAbB][0-9a-fA-F]:)" -}}
{{- range .Values.extraEnv -}}
{{- if not (regexMatch "^(RUST_LOG|RUST_BACKTRACE|OTEL_[A-Z0-9_]+)$" .name) -}}
{{- fail (printf "extraEnv allows only RUST_LOG, RUST_BACKTRACE, or OTEL_*; got %s" .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.networkPolicy.allowEgressCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "networkPolicy.allowEgressCidrs cannot contain empty, wildcard, loopback, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- range .Values.operator.ingress.allowCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "operator.ingress.allowCidrs cannot contain empty, wildcard, loopback, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.operator.enabled (not (trim .Values.operator.existingSecret)) -}}
{{- fail "operator.existingSecret must be set when operator.enabled is true" -}}
{{- end -}}
{{- if and (ne .Values.profile "embedded") (not (trim .Values.storage.database.existingSecret)) -}}
{{- fail "storage.database.existingSecret must be set for ha and distributed profiles" -}}
{{- end -}}
{{- $objDir := trimSuffix "/" (trim .Values.storage.objectStore.dir) -}}
{{- if or (eq $objDir "/var/lib/grdr") (hasPrefix "/var/lib/grdr/" $objDir) -}}
{{- fail "PF-04 violation: storage.objectStore.dir must be isolated outside /var/lib/grdr" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not (trim .Values.ingress.host)) -}}
{{- fail "ingress.host must be set when ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.tls.enabled) -}}
{{- fail "ingress.tls.enabled must remain true when ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.ingress.tls.enabled (not (trim .Values.ingress.tls.secretName)) -}}
{{- fail "ingress.tls.secretName must be set when ingress.tls.enabled is true" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled (not (trim .Values.operator.ingress.host)) -}}
{{- fail "operator.ingress.host must be set when operator.ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled (not .Values.operator.ingress.tls.enabled) -}}
{{- fail "operator.ingress.tls.enabled must remain true when operator.ingress.enabled is true" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled .Values.operator.ingress.tls.enabled (not (trim .Values.operator.ingress.tls.secretName)) -}}
{{- fail "operator.ingress.tls.secretName must be set when operator.ingress.tls.enabled is true" -}}
{{- end -}}
{{- $apiHost := trimSuffix "." (lower (trim .Values.ingress.host)) -}}
{{- $opHost := trimSuffix "." (lower (trim .Values.operator.ingress.host)) -}}
{{- if and .Values.ingress.enabled .Values.operator.enabled .Values.operator.ingress.enabled (eq $apiHost $opHost) -}}
{{- fail "D-70 violation: operator.ingress.host must be distinct from ingress.host" -}}
{{- end -}}
{{- if and .Values.operator.enabled .Values.operator.ingress.enabled (not .Values.operator.ingress.allowCidrs) -}}
{{- fail "operator.ingress.allowCidrs must not be empty when operator.ingress.enabled is true" -}}
{{- end -}}
{{- end -}}
