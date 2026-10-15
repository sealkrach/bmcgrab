{{- define "bmcgrab.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end }}
{{- define "bmcgrab.labels" -}}
app.kubernetes.io/name: bmcgrab
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | quote }}
{{- end }}
{{- define "bmcgrab.security" -}}
runAsNonRoot: true
runAsUser: 65532
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: ["ALL"] }
seccompProfile: { type: RuntimeDefault }
{{- end }}
