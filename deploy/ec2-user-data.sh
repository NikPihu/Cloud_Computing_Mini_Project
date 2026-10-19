#!/bin/bash
# EC2 user data for Amazon Linux 2023: installs Docker + Compose, clones the repo and starts
# NetGuard with CloudWatch logging. Paste into "Advanced details -> User data" when launching.
# Edit these two lines first:
REPO_URL="https://github.com/NikPihu/Cloud_Computing_Mini_Project.git"
BRANCH="claude/funny-allen-64e1fs"
set -euxo pipefail

dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user

# Docker Compose v2 + Buildx plugins
mkdir -p /usr/local/lib/docker/cli-plugins
ARCH=$(uname -m)
curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-${ARCH}" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
BX_ARCH=$([ "$ARCH" = "aarch64" ] && echo arm64 || echo amd64)
curl -fsSL "https://github.com/docker/buildx/releases/download/v0.17.1/buildx-v0.17.1.linux-${BX_ARCH}" \
  -o /usr/local/lib/docker/cli-plugins/docker-buildx
chmod +x /usr/local/lib/docker/cli-plugins/*

# 2 GB swap so model training during the image build fits on small instances
if [ ! -f /swapfile ]; then
  dd if=/dev/zero of=/swapfile bs=1M count=2048 && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
fi

# Region of this instance (IMDSv2)
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

cd /opt
git clone --branch "$BRANCH" "$REPO_URL" netguard
cd netguard
cat > .env <<ENV
SECRET_KEY=$(openssl rand -hex 32)
DEMO_PASSWORD=demo123
AWS_REGION=$REGION
CW_NAMESPACE=NetGuard
WEB_PORT=80
ENV
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build
