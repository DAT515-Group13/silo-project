#!/usr/bin/env bash
# One-time cluster setup. Safe to run again.
set -euo pipefail
unset HELM_DRIVER   # cluster releases use the default (Secret) driver
cd "$(dirname "$0")/.."

kubectl apply -f k8s/storage/local-path-storage.yaml
kubectl apply -f k8s/cluster/kube-network-policies.yaml
kubectl apply -f k8s/cluster/namespaces.yaml
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace monitoring pod-security.kubernetes.io/enforce=privileged --overwrite

helm repo add traefik https://traefik.github.io/charts
helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add grafana-community https://grafana-community.github.io/helm-charts
helm repo update

helm upgrade --install traefik traefik/traefik -n traefik --create-namespace \
  --version 42.1.3 -f k8s/cluster/traefik-values.yaml
helm upgrade --install metrics-server metrics-server/metrics-server -n kube-system \
  --version 3.13.0 -f k8s/cluster/metrics-server-values.yaml
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack -n monitoring \
  --version 92.14.1 -f k8s/cluster/monitoring-values.yaml --timeout 30m
helm upgrade --install loki grafana-community/loki -n monitoring \
  --version 20.0.2 -f k8s/cluster/loki-values.yaml --timeout 15m
helm upgrade --install alloy grafana/alloy -n monitoring \
  --version 1.14.4 -f k8s/cluster/alloy-values.yaml

kubectl -n monitoring create configmap silo-dashboard \
  --from-file=monitoring/grafana-dashboard.json --dry-run=client -o yaml \
  | kubectl label --local -f - grafana_dashboard=1 -o yaml | kubectl apply -f -
kubectl apply -f k8s/cluster/ci-deployer.yaml