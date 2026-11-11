#!/bin/bash
# Base setup for vex-micro (Ubuntu 24.04 Minimal, 1 GB). Safe to re-run.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== 1/4 swap (2 GB backup memory)"
if ! swapon --show | grep -q /swapfile; then
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile >/dev/null
  sudo swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swap.conf >/dev/null
sudo sysctl -q -p /etc/sysctl.d/99-swap.conf

echo "== 2/4 system updates (slow on a Micro, be patient)"
sudo apt-get update -q
sudo apt-get -y -q -o Dpkg::Options::=--force-confold upgrade

echo "== 3/4 basic tools + automatic security updates"
sudo apt-get install -y -q git curl ca-certificates unattended-upgrades htop nano
sudo dpkg-reconfigure -f noninteractive unattended-upgrades

echo "== 4/4 timezone"
sudo timedatectl set-timezone America/Edmonton

echo "== done"
free -h
df -h / | tail -1
uptime
