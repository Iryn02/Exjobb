output "master_ips" {
  value = {
    for k, v in multipass_instance.master : k => v.ipv4
  }
}

output "worker_ips" {
  value = {
    for k, v in multipass_instance.worker : k => v.ipv4
  }
}