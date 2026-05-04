1 #!/bin/bash
  2 CLUSTER_NAME=$1
  3 WORKER_KEY=$2
  4
  5 echo "waiting for ${CLUSTER_NAME}-master to be ready..."
  6
  7 until multipass exec ${CLUSTER_NAME}-master -- sudo k3s kubectl get nodes 2>/dev/null | grep -q "Ready"; do
  8   sleep 5
  9 done
 10
 11 echo "${CLUSTER_NAME}-master ready, fetching token and IP..."
 12
 13 TOKEN=$(multipass exec ${CLUSTER_NAME}-master -- sudo cat /var/lib/rancher/k3s/server/node-token)
 14 MASTER_IP=$(multipass info ${CLUSTER_NAME}-master | grep IPv4 | awk '{print $2}' | head -1)
 15
 16 echo "Joined ${WORKER_KEY} to ${CLUSTER_NAME} via ${MASTER_IP}..."
 17
 18 multipass exec ${WORKER_KEY} -- sudo sh -c "curl -sfL https://get.k3s.io | K3S_URL=https://${MASTER_IP}:6443 K3S_TOKEN=${TOKEN} sh -"
 19
 20 echo "${WORKER_KEY} done!"
