{{- define "grdr-server.podSpec" -}}
{{- include "grdr-server.validate" . -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
serviceAccountName: {{ include "grdr-server.serviceAccountName" . }}
automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .Values.security.runAsUser }}
  runAsGroup: {{ .Values.security.runAsGroup }}
  fsGroup: {{ .Values.security.fsGroup }}
  seccompProfile:
    type: RuntimeDefault
{{- if .Values.preflight.enabled }}
initContainers:
  - name: preflight
    image: {{ include "grdr-server.image" . }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    command:
      - "/usr/local/bin/grdr"
      - "server"
      - "preflight"
      - "--profile"
      - {{ .Values.profile | quote }}
      - "--data-dir"
      - "/var/lib/grdr"
      {{- if ne .Values.profile "embedded" }}
      - "--object-store-dir"
      - {{ .Values.storage.objectStore.dir | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.endpoint }}
      - "--object-store-endpoint"
      - {{ .Values.storage.objectStore.endpoint | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.bucket }}
      - "--object-store-bucket"
      - {{ .Values.storage.objectStore.bucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.backupBucket }}
      - "--backup-bucket"
      - {{ .Values.storage.objectStore.backupBucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.pathStyle }}
      - "--object-store-path-style"
      {{- end }}
      {{- if .Values.secrets.privateCAConfigMap }}
      - "--cert-file"
      - "/etc/grdr/certs/ca.crt"
      {{- end }}
      - "--check-pg-clock"
      - "--strict"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: {{ .Values.security.runAsUser }}
      capabilities:
        drop: ["ALL"]
    env:
      - name: GRDR_SERVER_PROFILE
        value: {{ .Values.profile | quote }}
      - name: GRDR_DATA_DIR
        value: "/var/lib/grdr"
      {{- if .Values.storage.objectStore.endpoint }}
      - name: GRDR_OBJECT_STORE_ENDPOINT
        value: {{ .Values.storage.objectStore.endpoint | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.bucket }}
      - name: GRDR_OBJECT_STORE_BUCKET
        value: {{ .Values.storage.objectStore.bucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.backupBucket }}
      - name: GRDR_BACKUP_BUCKET
        value: {{ .Values.storage.objectStore.backupBucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.region }}
      - name: GRDR_OBJECT_STORE_REGION
        value: {{ .Values.storage.objectStore.region | quote }}
      {{- end }}
      - name: GRDR_OBJECT_STORE_PATH_STYLE
        value: {{ .Values.storage.objectStore.pathStyle | quote }}
      {{- if .Values.storage.database.existingSecret }}
      - name: GRDR_POSTGRES_DSN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.database.existingSecret }}
            key: {{ .Values.storage.database.urlKey }}
      {{- end }}
      {{- if .Values.storage.nats.url }}
      - name: GRDR_NATS_URL
        value: {{ .Values.storage.nats.url | quote }}
      {{- end }}
      {{- if .Values.secrets.privateCAConfigMap }}
      - name: SSL_CERT_FILE
        value: "/etc/grdr/certs/ca.crt"
      {{- end }}
      {{- if .Values.storage.objectStore.existingSecret }}
      - name: AWS_ACCESS_KEY_ID
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.objectStore.existingSecret }}
            key: access-key
            optional: true
      - name: AWS_SECRET_ACCESS_KEY
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.objectStore.existingSecret }}
            key: secret-key
            optional: true
      {{- end }}
    volumeMounts:
      - name: boot-config
        mountPath: /etc/grdr/server.toml
        subPath: server.toml
        readOnly: true
      - name: data
        mountPath: /var/lib/grdr
      {{- if ne .Values.profile "embedded" }}
      - name: object-store-data
        mountPath: {{ .Values.storage.objectStore.dir | quote }}
      {{- end }}
      - name: tmp
        mountPath: /tmp
      {{- if .Values.secrets.privateCAConfigMap }}
      - name: private-ca
        mountPath: /etc/grdr/certs
        readOnly: true
      {{- end }}
      {{- if .Values.storage.objectStore.existingSecret }}
      - name: object-store-secret
        mountPath: /etc/grdr/secrets/object-store
        readOnly: true
      {{- end }}
      {{- if .Values.storage.nats.existingSecret }}
      - name: nats-secret
        mountPath: /etc/grdr/secrets/nats
        readOnly: true
      {{- end }}
{{- end }}
containers:
  - name: grdr-server
    image: {{ include "grdr-server.image" . }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    args:
      - "--bind"
      - "0.0.0.0:{{ .Values.service.targetPort }}"
      {{- if .Values.operator.enabled }}
      - "--operator-bind"
      - "0.0.0.0:{{ .Values.operator.listenPort }}"
      - "--operator-web-dir"
      - "/usr/share/grdr/operator-web"
      {{- end }}
      - "--data-dir"
      - "/var/lib/grdr"
      - "--profile"
      - {{ .Values.profile | quote }}
      {{- if ne .Values.profile "embedded" }}
      - "--object-store-dir"
      - {{ .Values.storage.objectStore.dir | quote }}
      {{- end }}
      - "--web-dir"
      - "/usr/share/grdr/web"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: {{ .Values.security.runAsUser }}
      capabilities:
        drop: ["ALL"]
    ports:
      - name: api
        containerPort: {{ .Values.service.targetPort }}
        protocol: TCP
      {{- if .Values.operator.enabled }}
      - name: operator
        containerPort: {{ .Values.operator.listenPort }}
        protocol: TCP
      {{- end }}
      {{- if .Values.metrics.enabled }}
      - name: metrics
        containerPort: {{ .Values.metrics.port }}
        protocol: TCP
      {{- end }}
    livenessProbe:
      httpGet:
        path: {{ .Values.probes.path | quote }}
        port: api
      initialDelaySeconds: {{ .Values.probes.initialDelaySeconds }}
      periodSeconds: {{ .Values.probes.periodSeconds }}
      timeoutSeconds: {{ .Values.probes.timeoutSeconds }}
      failureThreshold: {{ .Values.probes.failureThreshold }}
    readinessProbe:
      httpGet:
        path: {{ .Values.probes.path | quote }}
        port: api
      initialDelaySeconds: 5
      periodSeconds: 10
      timeoutSeconds: {{ .Values.probes.timeoutSeconds }}
      failureThreshold: {{ .Values.probes.failureThreshold }}
    env:
      - name: GRDR_SERVER_PROFILE
        value: {{ .Values.profile | quote }}
      - name: GRDR_DATA_DIR
        value: "/var/lib/grdr"
      - name: GRDR_WEB_DIR
        value: "/usr/share/grdr/web"
      {{- if .Values.operator.enabled }}
      - name: GRDR_OPERATOR_BIND
        value: "0.0.0.0:{{ .Values.operator.listenPort }}"
      - name: GRDR_OPERATOR_WEB_DIR
        value: "/usr/share/grdr/operator-web"
      {{- end }}
      {{- if .Values.storage.objectStore.endpoint }}
      - name: GRDR_OBJECT_STORE_ENDPOINT
        value: {{ .Values.storage.objectStore.endpoint | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.bucket }}
      - name: GRDR_OBJECT_STORE_BUCKET
        value: {{ .Values.storage.objectStore.bucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.backupBucket }}
      - name: GRDR_BACKUP_BUCKET
        value: {{ .Values.storage.objectStore.backupBucket | quote }}
      {{- end }}
      {{- if .Values.storage.objectStore.region }}
      - name: GRDR_OBJECT_STORE_REGION
        value: {{ .Values.storage.objectStore.region | quote }}
      {{- end }}
      - name: GRDR_OBJECT_STORE_PATH_STYLE
        value: {{ .Values.storage.objectStore.pathStyle | quote }}
      {{- if .Values.secrets.bootstrapExistingSecret }}
      - name: GRDR_API_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.secrets.bootstrapExistingSecret }}
            key: api-token
      - name: GRDR_ENROLL_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.secrets.bootstrapExistingSecret }}
            key: enroll-token
      {{- end }}
      {{- if and .Values.operator.enabled .Values.operator.existingSecret }}
      - name: GRDR_OPERATOR_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.operator.existingSecret }}
            key: operator-token
      - name: GRDR_STEP_UP_TOKEN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.operator.existingSecret }}
            key: step-up-token
            optional: true
      {{- end }}
      {{- if .Values.storage.database.existingSecret }}
      - name: GRDR_POSTGRES_DSN
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.database.existingSecret }}
            key: {{ .Values.storage.database.urlKey }}
      {{- end }}
      {{- if .Values.storage.nats.url }}
      - name: GRDR_NATS_URL
        value: {{ .Values.storage.nats.url | quote }}
      {{- end }}
      {{- if .Values.secrets.privateCAConfigMap }}
      - name: SSL_CERT_FILE
        value: "/etc/grdr/certs/ca.crt"
      {{- end }}
      {{- if .Values.storage.objectStore.existingSecret }}
      - name: AWS_ACCESS_KEY_ID
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.objectStore.existingSecret }}
            key: access-key
            optional: true
      - name: AWS_SECRET_ACCESS_KEY
        valueFrom:
          secretKeyRef:
            name: {{ .Values.storage.objectStore.existingSecret }}
            key: secret-key
            optional: true
      {{- end }}
      {{- with .Values.extraEnv }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    resources:
      {{- toYaml .Values.resources | nindent 6 }}
    volumeMounts:
      - name: boot-config
        mountPath: /etc/grdr/server.toml
        subPath: server.toml
        readOnly: true
      - name: data
        mountPath: /var/lib/grdr
      {{- if ne .Values.profile "embedded" }}
      - name: object-store-data
        mountPath: {{ .Values.storage.objectStore.dir | quote }}
      {{- end }}
      - name: tmp
        mountPath: /tmp
      {{- if .Values.secrets.privateCAConfigMap }}
      - name: private-ca
        mountPath: /etc/grdr/certs
        readOnly: true
      {{- end }}
      {{- if .Values.secrets.tlsExistingSecret }}
      - name: server-tls
        mountPath: /etc/grdr/tls
        readOnly: true
      {{- end }}
      {{- if .Values.operator.existingSecret }}
      - name: operator-secret
        mountPath: /etc/grdr/secrets/operator
        readOnly: true
      {{- end }}
      {{- if .Values.storage.objectStore.existingSecret }}
      - name: object-store-secret
        mountPath: /etc/grdr/secrets/object-store
        readOnly: true
      {{- end }}
      {{- if .Values.storage.nats.existingSecret }}
      - name: nats-secret
        mountPath: /etc/grdr/secrets/nats
        readOnly: true
      {{- end }}
      {{- if .Values.pkcs11Sidecar.enabled }}
      - name: pkcs11-sock
        mountPath: /run/grdr/keys
      {{- end }}
  {{- if .Values.pkcs11Sidecar.enabled }}
  - name: keys-pkcs11
    image: {{ include "grdr-server.pkcs11Image" . }}
    imagePullPolicy: {{ .Values.pkcs11Sidecar.image.pullPolicy }}
    args:
      - "--socket"
      - "/run/grdr/keys/pkcs11.sock"
      - "--module"
      - {{ .Values.pkcs11Sidecar.modulePath | quote }}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: {{ .Values.security.runAsUser }}
      capabilities:
        drop: ["ALL"]
    resources:
      {{- toYaml .Values.pkcs11Sidecar.resources | nindent 6 }}
    volumeMounts:
      - name: pkcs11-sock
        mountPath: /run/grdr/keys
      - name: tmp
        mountPath: /tmp
      {{- if .Values.pkcs11Sidecar.moduleVolumeClaimName }}
      - name: pkcs11-modules
        mountPath: /usr/lib/grdr/pkcs11
        readOnly: true
      {{- end }}
  {{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
volumes:
  - name: boot-config
    configMap:
      name: {{ include "grdr-server.fullname" . }}-boot
  - name: tmp
    emptyDir: {}
  {{- if or (ne .Values.profile "embedded") (not .Values.storage.embedded.persistence.enabled) }}
  - name: data
    emptyDir: {}
  {{- end }}
  {{- if ne .Values.profile "embedded" }}
  - name: object-store-data
    emptyDir: {}
  {{- end }}
  {{- if .Values.secrets.privateCAConfigMap }}
  - name: private-ca
    configMap:
      name: {{ .Values.secrets.privateCAConfigMap }}
  {{- end }}
  {{- if .Values.secrets.tlsExistingSecret }}
  - name: server-tls
    secret:
      secretName: {{ .Values.secrets.tlsExistingSecret }}
      defaultMode: 0400
  {{- end }}
  {{- if .Values.operator.existingSecret }}
  - name: operator-secret
    secret:
      secretName: {{ .Values.operator.existingSecret }}
      defaultMode: 0400
  {{- end }}
  {{- if .Values.storage.objectStore.existingSecret }}
  - name: object-store-secret
    secret:
      secretName: {{ .Values.storage.objectStore.existingSecret }}
      defaultMode: 0400
  {{- end }}
  {{- if .Values.storage.nats.existingSecret }}
  - name: nats-secret
    secret:
      secretName: {{ .Values.storage.nats.existingSecret }}
      defaultMode: 0400
  {{- end }}
  {{- if .Values.pkcs11Sidecar.enabled }}
  - name: pkcs11-sock
    emptyDir: {}
  {{- if .Values.pkcs11Sidecar.moduleVolumeClaimName }}
  - name: pkcs11-modules
    persistentVolumeClaim:
      claimName: {{ .Values.pkcs11Sidecar.moduleVolumeClaimName }}
      readOnly: true
  {{- end }}
  {{- end }}
{{- end -}}
