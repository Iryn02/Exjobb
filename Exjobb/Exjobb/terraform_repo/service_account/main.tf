terraform {
  required_providers {
    multipass = {
      source  = "larstobi/multipass"
      version = "~> 1.4"
    }
  }
}

locals {
  clusters = {
    "cluster1" = { master_ip = "10.201.182.10" }
    "cluster2" = { master_ip = "10.201.182.20" }
  }
  workers_per_cluster = 2
}

# Cloud-init för masters
resource "local_file" "master_cloud_init" {
  for_each = local.clusters
  filename = "${path.module}/${each.key}-master-cloud-init.yaml"
  content  = <<-EOT
#cloud-config
runcmd:
  - curl -sfL https://get.k3s.io | sh -
EOT
}

# Cloud-init för workers
resource "local_file" "worker_cloud_init" {
  for_each = local.clusters
  filename = "${path.module}/${each.key}-worker-cloud-init.yaml"
  content  = <<-EOT
#cloud-config
runcmd:
  - echo "worker ready"
EOT
}

# Masters - en per kluster
resource "multipass_instance" "master" {
  for_each       = local.clusters
  name           = "${each.key}-master"
  cpus           = 2
  memory         = "2G"
  disk           = "10G"
  image          = "lts"
  cloudinit_file = local_file.master_cloud_init[each.key].filename
}

# Workers - 2 per kluster
resource "multipass_instance" "worker" {
  for_each = {
    for pair in flatten([
      for cluster_name, _ in local.clusters : [
        for i in range(local.workers_per_cluster) : {
          key          = "${cluster_name}-worker-${i}"
          cluster_name = cluster_name
          index        = i
        }
      ]
    ]) : pair.key => pair
  }

  name           = each.value.key
  cpus           = 1
  memory         = "1G"
  disk           = "5G"
  image          = "lts"
  cloudinit_file = local_file.worker_cloud_init[each.value.cluster_name].filename
}

resource "null_resource" "join_workers" {
  for_each = {
    for pair in flatten([
      for cluster_name, cluster in local.clusters : [
        for i in range(local.workers_per_cluster) : {
          key          = "${cluster_name}-worker-${i}"
          cluster_name = cluster_name
          master_ip    = cluster.master_ip
        }
      ]
    ]) : pair.key => pair
  }
s
  depends_on = [multipass_instance.master, multipass_instance.worker]

  triggers = {
    worker_key = each.value.key
  }

  provisioner "local-exec" {
    command = "bash ${path.module}/../join_workers.sh ${each.value.cluster_name} ${each.value.key}"
  }
}

resource "null_resource" "vulnerable_service_account" {
  for_each = local.clusters

  depends_on = [multipass_instance.master]

  provisioner "local-exec" {
    command = <<-EOT
      multipass exec ${each.key}-master -- sudo kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnerable-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vulnerable-sa-binding
subjects:
- kind: ServiceAccount
  name: vulnerable-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
  namespace: default
spec:
  serviceAccountName: vulnerable-sa
  containers:
  - name: pwned
    image: bitnami/kubectl
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: service-account-token
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
  volumes:
  - name: service-account-token
    projected:
      sources:
      - serviceAccountToken:
          path: token
EOF
    EOT
  }
}