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
  image          = "jammy"
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

  depends_on = [multipass_instance.master, multipass_instance.worker]

  provisioner "local-exec" {
    command = "bash ${path.module}/../join_workers.sh  ${each.value.cluster_name} ${each.value.key}"
  }
}

resource "null_resource" "vulnerable_managed_identity" {
  for_each = local.clusters

  depends_on = [null_resource.join_workers]

  triggers = {
    cluster_name = each.key
  }

  provisioner "local-exec" {
    command = <<-EOT
      multipass exec ${each.key}-master -- sudo k3s kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: mock-imds-script
  namespace: default
data:
  server.py: |
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json
    class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        payload = {
          "access_token": "eyJGQUtFVE9LRU4.lab_credential_do_not_use",
          "client_id": "00000000-0000-0000-0000-000000000000",
          "expires_in": "3599",
          "resource": "https://management.azure.com/",
          "token_type": "Bearer"
        }
        self.wfile.write(json.dumps(payload).encode())
      def log_message(self, *args): pass
    HTTPServer(('', 8080), Handler).serve_forever()
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: mock-imds
  namespace: default
spec:
  selector:
    matchLabels:
      app: mock-imds
  template:
    metadata:
      labels:
        app: mock-imds
    spec:
      hostNetwork: true
      containers:
      - name: mock-imds
        image: python:3-slim
        securityContext:
          privileged: true
        command:
        - sh
        - -c
        - "apt-get update -qq && apt-get install -y -qq iptables 2>/dev/null; iptables -t nat -C PREROUTING -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || iptables -t nat -A PREROUTING -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-port 8080; exec python3 /scripts/server.py"
        volumeMounts:
        - name: script
          mountPath: /scripts
      volumes:
      - name: script
        configMap:
          name: mock-imds-script
---
apiVersion: v1
kind: Pod
metadata:
  name: victim-pod
  namespace: default
spec:
  containers:
  - name: victim
    image: curlimages/curl
    command: ["sleep", "infinity"]
EOF
    EOT
  }
}