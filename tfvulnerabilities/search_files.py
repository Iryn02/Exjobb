'''
Lateral Movement Lab — Security File Scanner
============================================
-*- encoding: utf-8 -*-
tfvulnerability v0.1.0
Bachelor of Network Engineering, MDU University
Authors: Johnny Norrman, Ida Rynger
Copyright © 2026, Ida Rynger Johnny Norrman.
See /LICENSE for licensing information

Scans Terraform and Kubernetes configuration files for potential security
misconfigurations and vulnerability indicators such as privileged containers,
exposed ports, and overly permissive RBAC settings.

Usage:
    python search_files.py

    When prompted, enter a file path or directory path to scan.
    Supports: .tf, .tf.json, .yaml, .yml

    Results are written to a numbered JSON file in the same directory:
        vulnFilesScript1.json, vulnFilesScript2.json, ...

Extending:
    To add support for additional file types, update SUPPORTED_EXTENSIONS
    in the SearchFile class:

        SUPPORTED_EXTENSIONS = ['.tf', '.tf.json', '.yaml', '.yml', '.toml']
'''

import subprocess
from pathlib import Path as p
import json
import re

class SearchFile:
    '''
    Scans a single configuration file for security misconfigurations.

    Searches Terraform and Kubernetes files for vulnerability indicators
    grouped by category: hostpath mounts, RBAC settings, privileged containers,
    network exposure, and security context settings. Results can be written
    to a numbered JSON file or returned in memory for batch scanning.

    Attributes:
        filename (str): Path to the file to be scanned.

    Example:
        scanner = SearchFile('terraform_repo/base/main.tf')
        scanner.file_search()
    '''

    HOSTPATH_KEYWORDS = ['hostPath:', 'path: /', 'path: /etc', 'path: /var']
    RBAC_KEYWORDS = ['serviceAccountName:', 'automountServiceAccountToken:', 'cluster-admin', 'ClusterRoleBinding']
    PRIVILEGED_KEYWORDS = ['privileged: true', 'hostNetwork: true', 'hostPID: true', 'hostIPC: true', 'access_token']
    NETWORK_KEYWORDS = ['hostPort:', 'type: NodePort', 'type: LoadBalancer', '0.0.0.0']
    SECURITY_KEYWORDS = ['runAsUser: 0', 'allowPrivilegeEscalation: true', '  add:', 'NET_ADMIN', 'SYS_ADMIN']
    SUPPORTED_EXTENSIONS = {'.tf', '.tf.json', '.yaml', '.yml'}

    def __init__(self, filename):
        '''
        Initialize the scanner with a target file.

        Args:
            filename (str): Path to the file to scan.
        '''
        self.filename = str(filename)


    def read_file(self):
        '''
        Read and return the contents of the target file.

        Returns:
            list[str]: A list of lines from the file.
        '''

        file_path = p(self.filename)
        if not file_path.is_absolute():
            file_path = p(__file__).parent / self.filename
        with open(file_path, 'r') as f:
            read_file = f.readlines()
        return read_file

    def write_to_file(self, temp_list, base_name='vulnFilesScript'):
        '''
         Write scan findings to a numbered JSON file.

        Automatically increments the file number to avoid overwriting
        previous results (e.g. vulnFilesScript1.json, vulnFilesScript2.json).

        Args:
            temp_list (dict): Findings to write, keyed by filename.
            base_name (str): Base name for the output file. Defaults to 'vulnFilesScript'.

        Returns:
            str: Path to the written output file.
        '''

        path = p(__file__).parent
        files = list(path.glob(f'{base_name}*.json'))

        numbers = []
        pattern = re.compile(rf'{base_name}(\d+)\.json')
        for f in files:
            match = pattern.search(f.name)
            if match:
                numbers.append(int(match.group(1)))

        next_number = max(numbers) + 1 if numbers else 1

        out_file = path / f'{base_name}{next_number}.json'
        with open(out_file, 'w') as f:
            json.dump(temp_list, f, indent=2)
        return str(out_file)

    def file_search(self):
        '''
        Validate the file type and run the vulnerability scan.

        Supported types are defined in SUPPORTED_EXTENSIONS. If the file
        type is not supported, the user is prompted to continue or abort.

        Returns:
            str: Path to the output file, or 'Stopping' if the user aborted.
        '''

        ext = p(self.filename).suffix
        if ext in self.SUPPORTED_EXTENSIONS:
            return self.vulnerabilities()
        else:
            if_not_correct = input('Filetype not supported. Do you want to continue anyway?[y/n]: ').lower()
            if if_not_correct == 'y':
                return self.vulnerabilities()
            elif if_not_correct == 'n':
                return 'Stopping'

    def search_keyword(self, keywords):
        '''
        Search the file for a specific list of keywords and write findings to file.

        Args:
            keywords (list[str]): Keywords to search for in the file.

        Returns:
            str: Path to the output file containing findings.
        '''

        temp_list = {self.filename: []}
        for line_number, i in enumerate(self.read_file(), start=1):
            for word in keywords:
                if word in i:
                    line = i.split(word, 1)
                    stripped_line = line[1].strip()
                    temp_list.setdefault(self.filename, []).append(f'{line_number}: {word} {stripped_line}')
        return self.write_to_file(temp_list)

    def vulnerabilities(self):
        '''
        Run a full vulnerability scan and write findings to a JSON file.

        Scans all keyword groups and extracts any comments found in the file.
        Results are grouped by category with a per-category count in 'summary'.

        Returns:
            str: Path to the output file containing findings.
        '''

        category_findings = {
            'hostpath': [],
            'rbac': [],
            'privileged': [],
            'network_exposure': [],
            'security_settings': [],
            'comments': [],
        }
        keyword_groups = [
            ('hostpath', self.HOSTPATH_KEYWORDS),
            ('rbac', self.RBAC_KEYWORDS),
            ('privileged', self.PRIVILEGED_KEYWORDS),
            ('network_exposure', self.NETWORK_KEYWORDS),
            ('security_settings', self.SECURITY_KEYWORDS),
        ]
        lines = self.read_file()
        for label, keywords in keyword_groups:
            for line_number, line in enumerate(lines, start=1):
                for word in keywords:
                    if word in line:
                        value = line.split(word, 1)[1].strip()
                        category_findings[label].append(
                            f'{line_number}: {word} {value}'
                        )
        for line_number, line in enumerate(lines, start=1):
            if '#' in line:
                comment = line.split('#', 1)[1].strip()
                if comment:
                    category_findings['comments'].append(
                        f'{line_number}: {comment}'
                    )

        all_findings = {
            self.filename: {
                'summary': {cat: len(hits) for cat, hits in category_findings.items()},
                'findings': category_findings,
            }
        }
        return self.write_to_file(all_findings)

    def vulnerabilities_in_memory(self):
        '''
        Run a full vulnerability scan and return findings in memory.

        Identical to vulnerabilities() but does not write to disk.
        Used by scan_directory() to batch results before writing once.

        Returns:
            dict: Findings keyed by filename. Each value is a dict with
                  'summary' (category counts) and 'findings' (hits per category).
        '''

        category_findings = {
            'hostpath': [],
            'rbac': [],
            'privileged': [],
            'network_exposure': [],
            'security_settings': [],
            'comments': [],
        }
        keyword_groups = [
            ('hostpath', self.HOSTPATH_KEYWORDS),
            ('rbac', self.RBAC_KEYWORDS),
            ('privileged', self.PRIVILEGED_KEYWORDS),
            ('network_exposure', self.NETWORK_KEYWORDS),
            ('security_settings', self.SECURITY_KEYWORDS),
        ]
        lines = self.read_file()
        for label, keywords in keyword_groups:
            for line_number, line in enumerate(lines, start=1):
                for word in keywords:
                    if word in line:
                        value = line.split(word, 1)[1].strip()
                        category_findings[label].append(
                            f'{line_number}: {word} {value}'
                        )
        for line_number, line in enumerate(lines, start=1):
            if '#' in line:
                comment = line.split('#', 1)[1].strip()
                if comment:
                    category_findings['comments'].append(
                        f'{line_number}: {comment}'
                    )

        return {
            self.filename: {
                'summary': {cat: len(hits) for cat, hits in category_findings.items()},
                'findings': category_findings,
            }
        }


def scan_directory(dir_path):
    '''
    Recursively scan a directory for vulnerable configuration files.

    If the given directory contains subdirectories, each subdirectory is
    treated as a separate repository and results are grouped by repo name.
    If the directory contains no subdirectories (i.e. it is already a single
    repo), the original flat behaviour is used.

    Searches for all .tf, .tf.json, .yaml and .yml files, runs
    vulnerabilities_in_memory() on each, then writes all findings
    to a single JSON output file.

    Args:
        dir_path (str): Path to the directory (or parent of repos) to scan.

    Returns:
        tuple:
            dict: All findings. Keyed by repo name when scanning multiple
                  repos, or by filename when scanning a single directory.
            str: Path to the written output file.

    Example:
        # Single repo
        findings, out_path = scan_directory('terraform_repo/')

        # Parent folder with multiple repos
        findings, out_path = scan_directory('all_repos/')
    '''

    dir_path = p(dir_path)
    extensions = ['**/*.tf', '**/*.tf.json', '**/*.yaml', '**/*.yml']

    subdirs = [d for d in sorted(dir_path.iterdir()) if d.is_dir()]
    is_multi_repo = len(subdirs) > 0

    if is_multi_repo:
        all_findings = {}
        for repo_dir in subdirs:
            repo_findings = {}
            for pattern in extensions:
                for file in sorted(repo_dir.glob(pattern)):
                    sf = SearchFile(str(file.resolve()))
                    findings = sf.vulnerabilities_in_memory()
                    for file_key, file_data in findings.items():
                        total_hits = sum(
                            count for cat, count in file_data['summary'].items()
                            if cat != 'comments'
                        )
                        if total_hits > 0:
                            repo_findings[file_key] = file_data

            repo_summary = {}
            for file_data in repo_findings.values():
                for cat, count in file_data['summary'].items():
                    if cat != 'comments':
                        repo_summary[cat] = repo_summary.get(cat, 0) + count

            all_findings[repo_dir.name] = {
                'summary': repo_summary,
                'files': repo_findings,
            }
    else:
        all_findings = {}
        for pattern in extensions:
            for file in sorted(dir_path.glob(pattern)):
                sf = SearchFile(str(file.resolve()))
                findings = sf.vulnerabilities_in_memory()
                for file_key, file_data in findings.items():
                    total_hits = sum(
                        count for cat, count in file_data['summary'].items()
                        if cat != 'comments'
                    )
                    if total_hits > 0:
                        all_findings[file_key] = file_data

    dummy = SearchFile('')
    out_path = dummy.write_to_file(all_findings)
    return all_findings, out_path


if __name__ == '__main__':
    path_input = input('Input file or directory: ')
    path = p(path_input)

    if path.is_dir():
        findings, out_path = scan_directory(path)
        subdirs = [d for d in path.iterdir() if d.is_dir()]
        if subdirs:
            total_files = sum(len(repo['files']) for repo in findings.values())
            total_hits = sum(
                count
                for repo in findings.values()
                for count in repo['summary'].values()
            )
            print(f'Skannade {len(findings)} repo(n), {total_files} fil(er), {total_hits} fynd. Resultat: {out_path}')
        else:
            total_hits = sum(
                count
                for file_data in findings.values()
                for cat, count in file_data['summary'].items()
                if cat != 'comments'
            )
            print(f'Skannade {len(findings)} fil(er), {total_hits} fynd. Resultat: {out_path}')
    else:
        ob_test = SearchFile(path_input)
        result = ob_test.file_search()
        print(result)
