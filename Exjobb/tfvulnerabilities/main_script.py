# Authors: Johnny Norrman, Ida Rynger
# Bachelor of Network Engineering - MDU University
# Thesis work: Lateral Movement in Kubernetes Clusters

import os
import search_files as sf
import subprocess as sp
import shutil
import argparse
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
TERRAFORM_REPO = SCRIPTS_DIR / 'terraform_repo'

ENVIRONMENTS = {
    '1': ('Base environment',    TERRAFORM_REPO / 'Base'),
    '2': ('Writable hostpath',   TERRAFORM_REPO / 'Hostpath'),
    '3': ('Managed identity',    TERRAFORM_REPO / 'managed_identity'),
    '4': ('Service account',     TERRAFORM_REPO / 'Service_account'),
}
class EnvManager:
    installed_list = ['terraform','kubectl']
    def __init__(self, ):
        #self.choice = choice
        pass

    def check_dependencies(self):# check if needed programs are installed
        results = {}
        for package in self.installed_list:
            result = sp.run(
                ["dpkg", "-s", package],
                stdout=sp.PIPE,
                stderr=sp.PIPE
            )
            results[package] = result.returncode == 0

        for package, installed in results.items():
            if installed:
                print(f'package {package} alredy installed')
            else:
                sp.run(
                    ['sudo','apt','install',package],
                       stdout=sp.PIPE,
                       stderr=sp.PIPE)
                print(f"Package {package} installed")
        try:
            sp.run(['sudo', 'snap', 'install', 'multipass'])
        except:
            print('Multipass alredy exists')

    def deploy_environment(self, choice): #get manifest files for correct assignment
        """
        Run terraform init + apply for the selected environment, then join workers.

        Args:
            choice: Menu option string ('1'–'4').
        """
        label, env_path = ENVIRONMENTS[choice]
        join_script = TERRAFORM_REPO / 'join_workers.sh'

        print(f'Deploying: {label}')

        result = sp.run(['terraform', 'init'], cwd=env_path, capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform init failed')
            return

        result = sp.run(['terraform', 'apply', '-auto-approve'], cwd=env_path, capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform apply failed')
            return

        sp.run(['bash', str(join_script)])

    def scan_files(self):
        """Run the pre-deploy security scanner on all terraform environments."""
        findings, out_path = sf.scan_directory(str(TERRAFORM_REPO))
        found_count = sum(len(v) for v in findings.values())
        print(f'Scanned {len(findings)} file(s), {found_count} findings. Results: {out_path}')

    def dispatch(self, choice):
        """
        Execute the action for the given choice.

        Args:
            choice: String '1'–'6'.
        """
        #self.check_dependencies()
        if choice in ENVIRONMENTS:
            self.deploy_environment(choice)
        elif choice == '5':
            self.scan_files()
        elif choice == '6':
            self.cleanup()
        else:
            print(f'Unknown choice: {choice}')

    def cleanup(self):
        """Tear down all VMs by running the cleanup script."""
        sp.run(['sudo', 'bash', str(SCRIPTS_DIR / 'cleanup.sh')])


def main():
    parser = argparse.ArgumentParser(
        description='Lateral Movement Lab — deploy and manage Kubernetes test environments'
    )
    parser.add_argument(
        'choice',
        nargs='?',
        choices=['1', '2', '3', '4', '5', '6'],
        help='1=Base, 2=Hostpath, 3=Managed identity, 4=Service account, 5=Scan, 6=Cleanup'
    )
    args = parser.parse_args()

    cli = EnvManager()
    if args.choice:
        cli.dispatch(args.choice)
    else:
        print('Something went wrog')


if __name__ == '__main__':
    main()
'''
# Authors: Johnny Norrman, Ida Rynger
# Bachelor of Network Engineering - MDU University
# Thesis work: Lateral Movement in Kubernetes Clusters

import searchFiles
import subprocess as sp
import shutil
import argparse
from pathlib import Path


SCRIPTS_DIR = Path(__file__).parent
TERRAFORM_REPO = SCRIPTS_DIR / 'terraform_repo'

ENVIRONMENTS = {
    '1': ('Base environment',    TERRAFORM_REPO / 'Base'),
    '2': ('Writable hostpath',   TERRAFORM_REPO / 'Hostpath'),
    '3': ('Managed identity',    TERRAFORM_REPO / 'managed_identity'),
    '4': ('Service account',     TERRAFORM_REPO / 'Service_account'),
}


class LabCLI:
    TOOLS = ['terraform', 'kubectl', 'multipass']

    def check_dependencies(self):
        """Check that required tools are installed; install missing ones via apt/snap."""
        for tool in self.TOOLS:
            if shutil.which(tool):
                print(f'{tool} already installed')
            elif tool == 'multipass':
                sp.run(['sudo', 'snap', 'install', 'multipass'])
                print('multipass installed')
            else:
                sp.run(['sudo', 'apt', 'install', '-y', tool])
                print(f'{tool} installed')

    def deploy_environment(self, choice):
        """
        Run terraform init + apply for the selected environment, then join workers.

        Args:
            choice: Menu option string ('1'–'4').
        """
        label, env_path = ENVIRONMENTS[choice]
        join_script = TERRAFORM_REPO / 'join_workers.sh'

        print(f'Deploying: {label}')

        result = sp.run(['terraform', 'init'], cwd=env_path, capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform init failed')
            return

        result = sp.run(['terraform', 'apply', '-auto-approve'], cwd=env_path, capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform apply failed')
            return

        sp.run(['bash', str(join_script)])

    def scan_files(self):
        """Run the pre-deploy security scanner on all terraform environments."""
        findings, out_path = searchFiles.scan_directory(str(TERRAFORM_REPO))
        found_count = sum(len(v) for v in findings.values())
        print(f'Scanned {len(findings)} file(s), {found_count} findings. Results: {out_path}')

    def cleanup(self):
        """Tear down all VMs by running the cleanup script."""
        sp.run(['sudo', 'bash', str(SCRIPTS_DIR / 'cleanup.sh')])

    def dispatch(self, choice):
        """
        Execute the action for the given choice.

        Args:
            choice: String '1'–'6'.
        """
        self.check_dependencies()
        if choice in ENVIRONMENTS:
            self.deploy_environment(choice)
        elif choice == '5':
            self.scan_files()
        elif choice == '6':
            self.cleanup()
        else:
            print(f'Unknown choice: {choice}')

    def menu(self):
        """Display the interactive menu and dispatch to the selected action."""
        print('<: Test environment for Kubernetes via Terraform :>')
        print('-' * 25)
        print('Choices:')
        print('-' * 25)
        for key, (label, _) in ENVIRONMENTS.items():
            print(f'{key}. {label}')
        print('5. Scan files')
        print('6. Cleanup environment')

        choice = input(':> ').strip()
        self.dispatch(choice)


def main():
    parser = argparse.ArgumentParser(
        description='Lateral Movement Lab — deploy and manage Kubernetes test environments'
    )
    parser.add_argument(
        'choice',
        nargs='?',
        choices=['1', '2', '3', '4', '5', '6'],
        help='1=Base, 2=Hostpath, 3=Managed identity, 4=Service account, 5=Scan, 6=Cleanup'
    )
    args = parser.parse_args()

    cli = LabCLI()
    if args.choice:
        cli.dispatch(args.choice)
    else:
        cli.menu()


if __name__ == '__main__':
    main()
'''