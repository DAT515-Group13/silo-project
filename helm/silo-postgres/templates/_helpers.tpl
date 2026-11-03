{{- define "silo.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "silo.azureEnv" -}}
- name: AZURE_STORAGE_CONNECTION_STRING
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.azure }}
      key: AZURE_STORAGE_CONNECTION_STRING
{{- end }}

{{- define "silo.egressPostgres" -}}
- to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: postgres
  ports:
    - { port: 5432, protocol: TCP }
{{- end }}

{{- define "silo.egressHttps" -}}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except: [10.0.0.0/8]
  ports:
    - { port: 443, protocol: TCP }
{{- end }}