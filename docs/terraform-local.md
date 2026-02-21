# Terraform Local Workflow

This page is for local Terraform inspection, planning, and state troubleshooting.

## Prerequisites

- Azure CLI authenticated to the target subscription
- Terraform installed
- Access to the Terraform state storage account/container

## Local init and plan

```bash
cd infra
export ARM_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
export TF_VAR_subscription_id="${ARM_SUBSCRIPTION_ID}"

terraform init \
  -backend-config="resource_group_name=rg-devsecops-aca" \
  -backend-config="storage_account_name=stdevsecopsacatfstate" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=devsecopsaca.tfstate" \
  -backend-config="use_azuread_auth=true"

terraform plan \
  -var="prefix=devsecopsaca" \
  -var="resource_group_name=rg-devsecops-aca" \
  -var="queue_name=tasks" \
  -var="create_apps=true" \
  -var="image_tag=<some-tag>"
```

Adjust values to match your environment.

## Common troubleshooting

### 403 during `terraform init`

Ensure the executing identity has data-plane access to the state account container (`Storage Blob Data Contributor` is the common requirement).

### Resource already exists

Import pre-existing resources into state:

```bash
terraform import <address> <resource-id>
```

### Stale state lease

```bash
az storage blob lease break \
  --account-name stdevsecopsacatfstate \
  --container-name tfstate \
  --blob-name devsecopsaca.tfstate \
  --auth-mode login
```

### Key Vault reader assignments

To manage persistent Key Vault secret-reader access in CI/CD, set GitHub variable `ACA_KV_SECRET_READER_OBJECT_IDS_JSON` to a JSON array of Entra object IDs, for example:

```json
["your-object-id-guid"]
```

## Related docs

- CI/CD behavior and deploy modes: `docs/cicd-workflows.md`
- Runtime/env settings: `docs/configuration-reference.md`
- Root README quickstart: `readme.md`
