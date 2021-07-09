{{- define "notary.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "notary.fullname" -}}
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

{{- define "notary.serverdburl" -}}
{{- if eq .Values.storage.flavor "mysql" -}}
{{- if .Values.storage.enabled -}}
{{ .Values.server.storageCredentials.user }}:%% .Env.PASSWORD %%@tcp(notary-db:3306)/notaryserver
{{- else -}}
{{ .Values.server.storageCredentials.user }}@tcp({{ .Values.storage.remote.host }}:{{ .Values.storage.remote.port }})/notaryserver
{{- end }}
{{- else if eq .Values.storage.flavor "postgres" -}}
{{- if .Values.storage.enabled -}}
{{ .Values.server.storageCredentials.user }}:%% .Env.PASSWORD %%@notary-db:5432/notaryserver{{ .Values.storage.additionalDbUrlParameters }}
{{- else -}}
{{ .Values.server.storageCredentials.user }}@{{ .Values.storage.remote.host }}:{{ .Values.storage.remote.port }}/notaryserver
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "notary.signerdburl" -}}
{{- if eq .Values.storage.flavor "mysql" -}}
{{- if .Values.storage.enabled -}}
{{ .Values.signer.storageCredentials.user }}:%% .Env.PASSWORD %%@tcp(notary-db:3306)/notarysigner
{{- else -}}
{{ .Values.signer.storageCredentials.user }}@tcp({{ .Values.storage.remote.host }}:{{ .Values.storage.remote.port }})/notarysigner
{{- end }}
{{- else if eq .Values.storage.flavor "postgres" -}}
{{- if .Values.storage.enabled -}}
{{ .Values.signer.storageCredentials.user }}:%% .Env.PASSWORD %%@notary-db:5432/notarysigner{{ .Values.storage.additionalDbUrlParameters }}
{{- else -}}
{{ .Values.signer.storageCredentials.user }}@{{ .Values.storage.remote.host }}:{{ .Values.storage.remote.port }}/notarysigner
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "notary.gunprefixes" -}}
{{- .Values.server.gunPrefixes | toJson -}}
{{ end -}}