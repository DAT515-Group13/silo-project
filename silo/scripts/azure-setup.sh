
#!/usr/bin/env bash
set -euo pipefail
umask 077

LOCATION="${LOCATION:-polandcentral}"
RG="${RG:-rg-silo}"
ENVS="${ENVS:-dev staging prod}"
CONTAINER="${CONTAINER:-files}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/silo-secrets}"
SUFFIX_FILE="$SECRETS_DIR/azure-suffix"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Verify that Azure CLI is logged in and has the expected subscription.
SUBSCRIPTION_ID="ca126efb-2653-4415-8510-1e151173560e"
az account set --subscription "$SUBSCRIPTION_ID"

echo "Subscription:"
az account show --query "{name:name,id:id,location:tenantId}" -o table

# Persist a random suffix so re-running the script reuses the same names.
if [ ! -s "$SUFFIX_FILE" ]; then
  head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SUFFIX_FILE"
fi
SUFFIX="$(cat "$SUFFIX_FILE")"

echo "Location: $LOCATION"
echo "Resource group: $RG"
echo "Storage account suffix: $SUFFIX"
echo "Environments: $ENVS"
echo
read -r -p "Create/reuse these Azure resources? Type YES to continue: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
  echo "Cancelled."
  exit 0
fi

az provider register --namespace Microsoft.Storage --wait
az group create --name "$RG" --location "$LOCATION" --output none

for env in $ENVS; do
  sa="cb${env}${SUFFIX}"
  echo "==> Setting up $env: $sa"

  if ! az storage account show \
    --name "$sa" --resource-group "$RG" >/dev/null 2>&1; then
    az storage account create \
      --name "$sa" \
      --resource-group "$RG" \
      --location "$LOCATION" \
      --sku Standard_LRS \
      --kind StorageV2 \
      --allow-blob-public-access false \
      --min-tls-version TLS1_2 \
      --https-only true \
      --tags project=silo environment="$env" \
      --output none
  fi

  conn="$(az storage account show-connection-string \
    --name "$sa" \
    --resource-group "$RG" \
    --query connectionString -o tsv)"

  az storage container create \
    --name "$CONTAINER" \
    --connection-string "$conn" \
    --public-access off \
    --output none

  printf 'AZURE_STORAGE_CONNECTION_STRING=%q\n' "$conn" \
    > "$SECRETS_DIR/azure-$env.env"
  chmod 600 "$SECRETS_DIR/azure-$env.env"
done

echo
echo "Finished. Secret files are in $SECRETS_DIR."
echo "Never commit these files or print their contents."
