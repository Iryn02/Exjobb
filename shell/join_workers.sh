#!/bin/bash
CLUSTER_NAME=$1
WORKER_KEY=$2

echo "waiting for ${CLUSTER_NAME}-master to be ready..."

until multipass exec ${CLUSTER_NAME}-master -- sudo k3s kubectl get nodes 2>/dev/null | grep -q "Ready"; do
  sleep 5
done

echo "${CLUSTER_NAME}-master ready, fetching token and IP..."

TOKEN=$(multipass exec ${CLUSTER_NAME}-master -- sudo cat /var/lib/rancher/k3s/server/node-token)
MASTER_IP=$(multipass info ${CLUSTER_NAME}-master | grep IPv4 | awk '{print $2}' | head -1)

echo "Joined ${WORKER_KEY} to ${CLUSTER_NAME} via ${MASTER_IP}..."

multipass exec ${WORKER_KEY} -- sudo sh -c "curl -sfL https://get.k3s.io | K3S_URL=https://${MASTER_IP}:6443 K3S_TOKEN=${TOKEN} sh -"

echo "${WORKER_KEY} done!"
