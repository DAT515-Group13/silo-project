# Helm charts

- `helm/silo`: the app (Deployment, Service, HPA, ConfigMap, Ingresses, NetworkPolicies, migrate hook, cleanup CronJob, PodMonitor).
- `helm/silo-postgres`: PostgreSQL StatefulSet, its NetworkPolicies and the nightly backup CronJob. Separate release because the migrate hook needs the database to exist first, and CI should not touch the database.

Secrets are created by `scripts/` and only referenced: `silo-app`, `silo-azure`, `silo-db`, `silo-tls`, `ghcr-pull`.
Release state is stored in ConfigMaps (`HELM_DRIVER=configmap`), so the CI service account needs no write access to Secrets.

```sh
export HELM_DRIVER=configmap
helm lint helm/silo -f helm/silo/values-dev.yaml --set image.tag=<sha>
helm upgrade --install silo-postgres helm/silo-postgres -n dev --wait
helm upgrade --install silo helm/silo -n dev -f helm/silo/values-dev.yaml \
  --set image.tag=<sha> --atomic --wait --timeout 8m
helm -n dev history silo
helm -n dev rollback silo <rev>