# Cloud Run deployment

This Terraform deploys the controlled demo only. It does not expose the service publicly by default; add IAM policy deliberately if public access is needed for the hackathon demo. Supply an immutable image digest. Do not pass production secrets to the service or agents.

```sh
gcloud auth application-default login
terraform -chdir=infra/cloudrun init
terraform -chdir=infra/cloudrun plan -var="project_id=$GOOGLE_CLOUD_PROJECT" -var="image=$IMAGE_DIGEST"
terraform -chdir=infra/cloudrun apply -var="project_id=$GOOGLE_CLOUD_PROJECT" -var="image=$IMAGE_DIGEST"
```
