'''
Lateral Movement Lab — Environment Manager
==========================================
-*- encoding: utf-8 -*-
tfvulnerability v0.1.0

Bachelor of Network Engineering, MDU University
Authors: Johnny Norrman, Ida Rynger
Copyright © 2026, Ida Rynger Johnny Norrman.
See /LICENSE for licensing information.

Provides a CLI for deploying and managing pre-configured Kubernetes test
environments used to study lateral movement attack vectors. Environments
are provisioned through Terraform and Multipass VMs.

Usage:
    python main.py <choice>

    Choices:
        1 - Deploy base environment
        2 - Deploy writable hostpath environment
        3 - Deploy managed identity environment
        4 - Deploy service account environment
        5 - Scan Terraform files for misconfigurations
        6 - Cleanup and tear down all VMs
'''
import subprocess as sp
import argparse
from pathlib import Path
import search_files as sf

SCRIPTS_DIR = Path(__file__).parent
TERRAFORM_REPO = SCRIPTS_DIR / 'terraform_repo'

ENVIRONMENTS = {
    '1': ('Base environment',    TERRAFORM_REPO / 'Base'),
    '2': ('Writable hostpath',   TERRAFORM_REPO / 'Hostpath'),
    '3': ('Managed identity',    TERRAFORM_REPO / 'managed_identity'),
    '4': ('Service account',     TERRAFORM_REPO / 'Service_account'),
}
class EnvManager:
    '''
    Manages deployment and teardown of Kubernetes test environments via Terraform.

    Provides an interface for deploying pre-configured vulnerable Kubernetes
    environments used to study lateral movement attack vectors. Environments
    are defined in ENVIRONMENTS and provisioned through Terraform and Multipass VMs.

    Attributes:
        terraform_repo (Path): Path to the Terraform repository containing environment configs.
        scripts_dir (Path): Path to the directory containing helper scripts (e.g. cleanup.sh).

    Example:
        manager = EnvManager()
        manager.dispatch('1')  # Deploys the base Kubernetes environment
    '''

    def __init__(self, ):
        self.terraform_repo = TERRAFORM_REPO
        self.scripts_dir = SCRIPTS_DIR

    def deploy_environment(self, choice): #get manifest files for correct assignment
        """
        Run terraform init + apply for the selected environment,
        then join_workers.sh joins workers to the clusters

        Args:
            choice: Menu option string ('1'–'4').
        """
        label, env_path = ENVIRONMENTS[choice]
        join_script = self.terraform_repo / 'join_workers.sh'

        print(f'Deploying: {label}')

        result = sp.run(['terraform', 'init'], cwd=env_path,
                        capture_output=True, text=True, check=False)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform init failed')
            return

        result = sp.run(['terraform', 'apply', '-auto-approve'],
                        cwd=env_path, capture_output=True, text=True, check=False)
        print(result.stdout, result.stderr)
        if result.returncode != 0:
            print('terraform apply failed')
            return

        sp.run(['bash', str(join_script)], check=True)

    def scan_files(self):
        '''
        Prompt the user for a path, then run a security scan on the target.

        Accepts a file path or directory path. Defaults to the Terraform repo
        if the user presses Enter without input. Prints a summary of findings
        and the path to the full results JSON file.
        '''

        prompt = f'Enter path to scan (default: {self.terraform_repo}): '
        user_input = input(prompt).strip()
        scan_path = user_input if user_input else str(self.terraform_repo)

        path = Path(scan_path)
        if not path.exists():
            print(f'Path not found: {scan_path}')
            return

        if path.is_dir():
            findings, out_path = sf.scan_directory(scan_path)
            subdirs = [d for d in path.iterdir() if d.is_dir()]
            if subdirs:
                total_files = sum(len(repo['files']) for repo in findings.values())
                total_hits = sum(
                    count
                    for repo in findings.values()
                    for count in repo['summary'].values()
                )
                print(f'Scanned {len(findings)} repo(s), {total_files} file(s), {total_hits} findings. Results: {out_path}')
            else:
                total_hits = sum(
                    count
                    for file_data in findings.values()
                    for cat, count in file_data['summary'].items()
                    if cat != 'comments'
                )
                print(f'Scanned {len(findings)} file(s), {total_hits} findings. Results: {out_path}')
        else:
            scanner = sf.SearchFile(scan_path)
            out_path = scanner.file_search()
            print(f'Results: {out_path}')

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
            self.run_cleanup()
        else:
            print(f'Unknown choice: {choice}')

    def run_cleanup(self):
        '''
        Tear down all VMs and instances using bash script cleanup.sh
        '''
        sp.run(['sudo', 'bash', str(self.scripts_dir / 'cleanup.sh')], check=True)


def main():
    '''
    Entry point for the Lateral Movement Lab CLI.

    Parses command-line arguments and dispatches the selected action
    via EnvManager. If a valid choice ('1'–'6') is provided as an
    argument, it is executed directly without an interactive prompt.

    Command-line arguments:
        choice: Optional action to perform.
            1 = Deploy base environment
            2 = Deploy writable hostpath environment
            3 = Deploy managed identity environment
            4 = Deploy service account environment
            5 = Scan terraform files
            6 = Cleanup all VMs
    '''
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
