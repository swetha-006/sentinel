terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
      version = ">= 5.20.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "asia-south1"
}

variable "image" {
  type        = string
  description = "Immutable container image URI including digest"
}

resource "google_cloud_run_v2_service" "payments_demo" {
  name                = "sentinel-payments-demo"
  location            = var.region
  project             = var.project_id
  deletion_protection = true

  template {
    containers {
      image = var.image
      ports {
        container_port = 8080
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
    scaling {
      max_instance_count = 2
    }
  }
}

output "service_uri" {
  value = google_cloud_run_v2_service.payments_demo.uri
}
