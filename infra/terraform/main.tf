# SENTINEL LAB — Terraform wrapper around the Docker Compose stack.
#
# This uses the Terraform Docker provider purely to give the lab a
# one-command, declarative spin-up path for users who prefer
# infra-as-code over `docker compose up` directly. It builds the exact
# same images and networks defined in docker-compose.yml -- the isolation
# guarantee (internal: true networks) is expressed identically here.
terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_network" "attacker_net" {
  name     = "sentinel-lab-attacker-net"
  internal = true
}

resource "docker_network" "target_net" {
  name     = "sentinel-lab-target-net"
  internal = true
}

resource "docker_network" "public_net" {
  name = "sentinel-lab-public-net"
}

resource "docker_image" "web" {
  name = "sentinel-lab/web:latest"
  build {
    context = "${path.module}/../../targets/web"
  }
}

resource "docker_container" "web" {
  count = 3
  name  = "sentinel-lab-web-${count.index}"
  image = docker_image.web.image_id
  networks_advanced {
    name = docker_network.target_net.name
  }
}

# See infra/k8s/ for the full Kubernetes manifest set (primary deployment
# target per the architecture doc) and docker-compose.yml for the complete
# service graph (attackers, defense engine, observability, globe, reports)
# that this Terraform stub intentionally keeps minimal.
