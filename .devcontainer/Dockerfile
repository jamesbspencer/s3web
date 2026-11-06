FROM mcr.microsoft.com/devcontainers/go:1-1.23-bookworm

ARG TERRAFORM_VERSION=1.9.8

# Remove stale yarnpkg apt source from base image and install Terraform CLI + jq
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl unzip jq ca-certificates \
    && ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip" -o /tmp/terraform.zip \
    && unzip /tmp/terraform.zip -d /usr/local/bin \
    && rm -f /tmp/terraform.zip \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*
