#!/usr/bin/env bash
# Usage: scripts/backup-smoke-test.sh <dev|prod>
# Restores the newest backup into a scratch database and checks it has users.
set -euo pipefail
NS="${1:?Usage: $0 <dev|prod>}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-26}"

if ! kubectl -n "$NS" get cronjob postgres-backup >/dev/null 2>&1; then
  echo "No postgres-backup CronJob in $NS, skipping"
  exit 0
fi

kubectl -n "$NS" delete job backup-smoke-test --ignore-not-found --wait=true
kubectl -n "$NS" apply -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: backup-smoke-test
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: postgres-backup
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: download
          image: mcr.microsoft.com/azure-cli:2.91.0
          command:
            - sh
            - -c
            - |
              set -e
              az storage blob list -c backups --only-show-errors \
                --query 'sort_by([], &properties.lastModified)[-1].{n:name, m:properties.lastModified}' -o tsv > /backup/latest
              name=\$(cut -f1 /backup/latest)
              [ -n "\$name" ] || { echo "no backups found"; exit 1; }
              az storage blob download -c backups -n "\$name" -f /backup/silo.dump --only-show-errors >/dev/null
          securityContext:
            runAsUser: 10001
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: HOME
              value: /tmp
            - name: AZURE_STORAGE_CONNECTION_STRING
              valueFrom: { secretKeyRef: { name: silo-azure, key: AZURE_STORAGE_CONNECTION_STRING } }
          volumeMounts:
            - { name: backup, mountPath: /backup }
            - { name: tmp, mountPath: /tmp }
      containers:
        - name: restore
          image: postgres:17
          command:
            - bash
            - -c
            - |
              set -euo pipefail
              read -r name modified < /backup/latest
              age=\$(( ( \$(date +%s) - \$(date -d "\$modified" +%s) ) / 3600 ))
              echo "backup: \$name (\${age}h old, \$(du -h /backup/silo.dump | cut -f1))"
              [ "\$age" -lt "$MAX_AGE_HOURS" ] || { echo "FAIL: backup older than ${MAX_AGE_HOURS}h"; exit 1; }
              db=silo_backup_check
              trap 'dropdb --if-exists "\$db"' EXIT
              dropdb --if-exists "\$db"
              createdb "\$db"
              pg_restore -d "\$db" --no-owner --exit-on-error /backup/silo.dump
              for t in users teams files share_links audit_log; do
                echo "\$t: \$(psql -d "\$db" -tAc "select count(*) from \$t")"
              done
              [ "\$(psql -d "\$db" -tAc 'select count(*) from users')" -gt 0 ] || { echo "FAIL: no users in backup"; exit 1; }
              echo "OK"
          securityContext:
            runAsUser: 999
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: PGHOST
              value: postgres
            - name: PGUSER
              valueFrom: { secretKeyRef: { name: silo-db, key: POSTGRES_USER } }
            - name: PGDATABASE
              valueFrom: { secretKeyRef: { name: silo-db, key: POSTGRES_DB } }
            - name: PGPASSWORD
              valueFrom: { secretKeyRef: { name: silo-db, key: POSTGRES_PASSWORD } }
          volumeMounts:
            - { name: backup, mountPath: /backup }
      volumes:
        - { name: backup, emptyDir: {} }
        - { name: tmp, emptyDir: {} }
YAML

ok=0
kubectl -n "$NS" wait --for=condition=complete job/backup-smoke-test --timeout=600s || ok=$?
kubectl -n "$NS" logs job/backup-smoke-test -c download || true
kubectl -n "$NS" logs job/backup-smoke-test -c restore || true
exit "$ok"
