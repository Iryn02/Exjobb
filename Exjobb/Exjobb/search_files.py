# Authors: Johnny Norrman, Ida Rynger
# Bachelor of Network Engineering - MDU University
# Thesis work: Lateral Movement in Kubernetes Clusters

import subprocess # to run linux commands
from pathlib import Path as p # for filepaths
import json
import re

#skript ska kunna läsa .tf filer, yml filer (kubernetes)
#Kolla efter fraser som kan vara lösenord eller liknande med Dragr
#vilka portar som är öppna
#certifikat och liknande

class SearchFile:
    HOSTPATH_KEYWORDS = ['hostPath:', 'path: /', 'path: /etc', 'path: /var']
    RBAC_KEYWORDS = ['serviceAccountName:', 'automountServiceAccountToken:', 'cluster-admin', 'ClusterRoleBinding']
    PRIVILEGED_KEYWORDS = ['privileged: true', 'hostNetwork: true', 'hostPID: true', 'hostIPC: true', 'access_token']
    NETWORK_KEYWORDS = ['hostPort:', 'type: NodePort', 'type: LoadBalancer', '0.0.0.0']
    SECURITY_KEYWORDS = ['runAsUser: 0', 'allowPrivilegeEscalation: true', '  add:', 'NET_ADMIN', 'SYS_ADMIN']

    def __init__(self, filename):
        self.filename = str(filename)


    def read_file(self):
        file_path = p(self.filename)
        if not file_path.is_absolute():
            file_path = p(__file__).parent / self.filename
        with open(file_path, 'r') as f:
            read_file = f.readlines()
        return read_file

    def write_to_file(self, temp_list, base_name='vulnFilesScript'):
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
        if self.filename.endswith('.tf') or self.filename.endswith('.tf.json'):
            return self.vulnerabilities()
        elif self.filename.endswith('.yaml') or self.filename.endswith('.yml'):
            return self.vulnerabilities()
        else:
            if_not_correct = input('Filetype not supported. Do you want to continue anyway?[y/n]: ').lower()
            if if_not_correct == 'y':
                return self.vulnerabilities()
            elif if_not_correct == 'n':
                return 'Stopping'

    def search_keyword(self, keywords):
        temp_list = {self.filename: []}
        for line_number, i in enumerate(self.read_file(), start=1):
            for word in keywords:
                if word in i:
                    line = i.split(word, 1)
                    stripped_line = line[1].strip()
                    temp_list.setdefault(self.filename, []).append(f'{line_number}: {word} {stripped_line}')
        return self.write_to_file(temp_list)

    def vulnerabilities(self):
        all_findings = {self.filename: []}
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
                        all_findings[self.filename].append(
                            f'{line_number} [{label}]: {word} {value}'
                        )
        for line_number, line in enumerate(lines, start=1):
            if '#' in line:
                comment = line.split('#', 1)[1].strip()
                if comment:
                    all_findings[self.filename].append(
                        f'{line_number} [comment]: {comment}'
                    )
        return self.write_to_file(all_findings)


def scan_directory(dir_path):
    dir_path = p(dir_path)
    extensions = ['**/*.tf', '**/*.tf.json', '**/*.yaml', '**/*.yml']
    all_findings = {}

    for pattern in extensions:
        for file in sorted(dir_path.glob(pattern)):
            sf = SearchFile(str(file.resolve()))
            findings = sf.vulnerabilities()
            # read back the JSON we just wrote to merge into all_findings
            with open(findings) as f:
                file_findings = json.load(f)
            for file_key, hits in file_findings.items():
                if hits:
                    all_findings[file_key] = hits

    dummy = SearchFile('')
    out_path = dummy.write_to_file(all_findings)
    return all_findings, out_path


if __name__ == '__main__':
    path_input = input('Input file or directory: ')
    path = p(path_input)

    if path.is_dir():
        findings, out_path = scan_directory(path)
        found_count = sum(len(v) for v in findings.values())
        print(f'Skannade {len(findings)} fil(er), {found_count} fynd. Resultat: {out_path}')
    else:
        ob_test = SearchFile(path_input)
        result = ob_test.file_search()
        print(result)