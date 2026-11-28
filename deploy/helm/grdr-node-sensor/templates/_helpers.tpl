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
{{- $badCidr := "^(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[01]$|0\\.|127\\.|(?:[0-9]|[1-9][0-9]|1[0-8][0-9]|19[01])\\.[^/]+/[0-7]$|169\\.(?:254\\.|[^/]+/[0-8]$|(?:1[2-9][0-9]|2[0-4][0-9]|25[0-5])\\.[^/]+/(?:9|1[0-5])$)|[0-9A-Fa-f:]+/[0-7]$|(?:0+:)+:(?:0+:)*0*/|::(?:0+:)*0*/|(?:0+:){1,7}0+/|(?:::(?:0+:)*|(?:0+:){1,7}:?(?:0+:)*)0*1/|(?:(?:0+:)+:(?:0+:)*|::(?:0+:)*|(?:0+:){5})(?:[^/]*/(?:[0-7]?[0-9]|80)$|[89a-fA-F][0-9a-fA-F]{3}:[^/]+/81$|[c-fC-F][0-9a-fA-F]{3}:[^/]+/82$|[eEfF][0-9a-fA-F]{3}:[^/]+/83$|[fF][0-9a-fA-F]{3}:[^/]+/84$|[fF][89a-fA-F][0-9a-fA-F]{2}:[^/]+/85$|[fF][c-fC-F][0-9a-fA-F]{2}:[^/]+/86$|[fF][eEfF][0-9a-fA-F]{2}:[^/]+/87$|[fF]{2}[0-9a-fA-F]{2}:[^/]+/88$|[fF]{2}[89a-fA-F][0-9a-fA-F]:[^/]+/89$|[fF]{2}[c-fC-F][0-9a-fA-F]:[^/]+/90$|[fF]{2}[eEfF][0-9a-fA-F]:[^/]+/91$|[fF]{3}[0-9a-fA-F]:[^/]+/92$|[fF]{3}[89a-fA-F]:[^/]+/93$|[fF]{3}[c-fC-F]:[^/]+/94$|[fF]{3}[eEfF]:[^/]+/95$|[fF]{4}:)|[fF][dD][0-9a-fA-F]{2}:[^/]+/8$|[fF][dD][0-7][0-9a-fA-F]:[^/]+/(?:9|1[0-5])$|[fF][dD]00:[^/]+/16$|[fF][dD]00:(?:[0-7][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/17$|[fF][dD]00:(?:[0-3][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/18$|[fF][dD]00:(?:[01][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/19$|[fF][dD]00:(?:0[0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/20$|[fF][dD]00:0*[89a-fA-F][0-9a-fA-F]{2}:[^/]+/21$|[fF][dD]00:0*[c-fC-F][0-9a-fA-F]{2}:[^/]+/22$|[fF][dD]00:0*[eEfF][0-9a-fA-F]{2}:[^/]+/23$|[fF][dD]00:0*[eE][0-9a-fA-F]{2}:[^/]+/24$|[fF][dD]00:0*[eE][89a-fA-F][0-9a-fA-F]:[^/]+/25$|[fF][dD]00:0*[eE][c-fC-F][0-9a-fA-F]:[^/]+/26$|[fF][dD]00:0*[eE][cCdD][0-9a-fA-F]:[^/]+/27$|[fF][dD]00:0*[eE][cC][0-9a-fA-F]:[^/]+/28$|[fF][dD]00:0*[eE][cC][0-7]:[^/]+/29$|[fF][dD]00:0*[eE][cC][0-3]:[^/]+/30$|[fF][dD]00:0*[eE][cC][23]:[^/]+/31$|[fF][dD]00:0*[eE][cC]2[:/]|[fF][eE][0-9a-fA-F]{2}:[^/]+/8$|[fF][eE][89aAbB][0-9a-fA-F]:)" -}}
{{- if .Values.server.sslInsecureSkipVerify -}}
{{- fail "server.sslInsecureSkipVerify is forbidden" -}}
{{- end -}}
{{- if and .Values.sidecar.enabled .Values.sidecar.mutatingWebhook.enabled (not .Values.sidecar.mutatingWebhook.caBundle) (not .Values.sidecar.mutatingWebhook.certManagerInjectCAFrom) -}}
{{- fail "sidecar.mutatingWebhook requires either caBundle or certManagerInjectCAFrom when enabled" -}}
{{- end -}}
{{- range .Values.networkPolicy.allowEgressCidrs -}}
{{- if or (not .) (regexMatch $badCidr .) -}}
{{- fail (printf "networkPolicy.allowEgressCidrs cannot contain empty, wildcard, loopback, or IMDS/link-local CIDR %q" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.serverNamespace) (not .Values.networkPolicy.allowEgressCidrs) -}}
{{- fail "networkPolicy requires non-empty serverNamespace or allowEgressCidrs when enabled" -}}
{{- end -}}
{{- end -}}
