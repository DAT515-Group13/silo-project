ENV ?= dev
TAG ?= $(shell git rev-parse HEAD)
export HELM_DRIVER := configmap

.PHONY: lint secrets db deploy status verify uninstall

lint:
	helm lint helm/silo -f helm/silo/values-$(ENV).yaml --set image.tag=$(TAG)
	helm lint helm/silo-postgres

secrets:
	scripts/k8s-create-db-secret.sh $(ENV)
	scripts/k8s-create-app-secret.sh $(ENV)
	scripts/k8s-create-secrets.sh $(ENV)

db:
	helm upgrade --install silo-postgres helm/silo-postgres -n $(ENV) --wait --timeout 5m

deploy:
	helm upgrade --install silo helm/silo -n $(ENV) -f helm/silo/values-$(ENV).yaml \
	  --set image.tag=$(TAG) --atomic --wait --timeout 8m --history-max 5

status:
	helm -n $(ENV) list
	kubectl -n $(ENV) get pods,hpa,ingress

verify:
	scripts/smoke-test.sh $(ENV)

uninstall:
	helm -n $(ENV) uninstall silo
	helm -n $(ENV) uninstall silo-postgres