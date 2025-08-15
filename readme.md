DevSecOps Microservice on Azure

Spin up a tiny **event-driven system** on Azure using **Terraform** and **GitHub Actions (OIDC)**:

- **FastAPI** “producer” (HTTP) → pushes JSON to **Azure Service Bus** (queue)
    
- **Worker** “consumer” → reads the queue and logs processing
    
- **KEDA** auto-scales the worker based on queue depth
    
- **Key Vault** holds the Service Bus connection string; apps read it via **managed identity**
    
- **Application Insights** + **Log Analytics** for observability
    
- **Container Apps** (Consumption) for serverless containers
    
- **ACR** for container images
    
- **Terraform backend** in a Storage Account (RBAC/AAD auth)

> This README explains **what you get**, **how it works**, **how to run it**, **how to test/observe it**, and **how to clean up**. It also captures the snags we hit (and fixes), plus ideas for future expansion.