#!/bin/bash

echo "Rensar multipass instanser..."
sudo multipass list --format csv | tail -n +2 | cut -d',' -f1 | while read instance; do
    echo "Tar bort instans: $instance"
    sudo multipass delete $instance
done
sudo multipass purge

echo "Tar bort lock-, yaml-, tfstate-filer och .terraform mapp..."

TERRAFORM_REPO="/home/terra/exjobb/scripts/terraform_repo"

for dir in "$TERRAFORM_REPO"/*/; do
    if [ -d "$dir" ]; then
        echo "Rensar mapp: $dir"
        rm -rf "$dir".terraform.lock.hcl
        rm -f "$dir"*.yaml
        rm -f "$dir"terraform.tfstate
        rm -f "$dir"terraform.tfstate.backup
        rm -rf "$dir".terraform
    fi
done

echo "Klart!"