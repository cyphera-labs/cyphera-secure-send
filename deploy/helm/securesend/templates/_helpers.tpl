{{- define "securesend.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "securesend.fullname" -}}
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

{{- define "securesend.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "securesend.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "securesend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securesend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "securesend.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "securesend.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "securesend.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "securesend.oidcSecretName" -}}
{{- if .Values.oidc.existingSecret -}}
{{- .Values.oidc.existingSecret -}}
{{- else -}}
{{- printf "%s-oidc" (include "securesend.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The configuration file as rendered into the ConfigMap. */}}
{{- define "securesend.config" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- $_ := set $cfg "storage" (dict "backend" .Values.storage.backend) -}}
{{- if .Values.branding.existingConfigMap -}}
{{- $b := index $cfg "branding" -}}
{{- if .Values.branding.logoFile -}}{{- $_ := set $b "logo_path" (printf "/branding/%s" .Values.branding.logoFile) -}}{{- end -}}
{{- if .Values.branding.faviconFile -}}{{- $_ := set $b "favicon_path" (printf "/branding/%s" .Values.branding.faviconFile) -}}{{- end -}}
{{- end -}}
{{- $server := index $cfg "server" -}}
{{- $_ := set $server "bind" "0.0.0.0:8080" -}}
{{- $_ := set $server "management_bind" (printf "0.0.0.0:%d" (int .Values.management.port)) -}}
{{- toYaml $cfg -}}
{{- end -}}
