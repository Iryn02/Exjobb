# Authors: Johnny Norrman, Ida Rynger
# Bachelor of Network Engineering - MDU University
# Thesis work: Lateral Movement in Kubernetes Clusters

import searchFiles as sf
import subprocess as sp
import os


class Main_Gui:
    installed_list = ['terraform','kubectl']
    def __init__(self, input):
        self.input = input
    
    
    def check_dependencies(self): # check if needed programs are installed
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
            
    def fetch_mainfest(self, choice): #get manifest files for correct assignment
        ENVIRONMENTS = {'1' : '/home/$USER/Exjobb/scripts/Base/',
                        '2' : '/home/$USER/Exjobb/scripts/Hostpath/',
                        '3' : '/home/$USER/Exjobb/scripts/managed_identity/', 
                        '4' : '/home/$USER/Exjobb/scripts/Service_account/',
                        '5' : '/home/$USER/Exjobb/scripts/',
                        '6' : '/home/$USER/Exjobb/scripts/'}
        base_path = ENVIRONMENTS[choice]
        contents = {}
        try:
            for filename in ['main.tf', 'outputs.tf']:
                with open(os.path.join(base_path, filename), 'r') as f:
                    contents[filename] = f.read()
                    
            result = sp.run(['terraform', 'init'], 
                            cwd=base_path,
                            capture_output=True,
                            text=True)
            print(result.stderr, result.stdout)
            if result.returncode == 0:
                result = sp.run(['terraform', 'apply', '-auto-approve'],
                                cwd=base_path, 
                                capture_output=True,
                                text=True)
                print(result.stderr, result.stdout)
                if result.returncode == 0:
                    sp.run(['bash','/home/terra/git/exjobb/scripts/join_workers.sh']) #filväg innan join_workers
            if choice == '5':
                sp.run([sf])
            if choice == '6':
                sp.run(['sudo','bash','/home/terra/git/exjobb/scripts/cleanup.sh'])
                
            else:
                print('Terraform error', result.stderr, result.stdout)
                
            return contents
        except: 
            print('terraform error', result.stderr, result.stdout)
    
    #def run_terraform(self): #terraform init/apply...
     #   result = sp.run(['terraform','init'], cwd=s
        
     #   pass

    def gui(self):  #all prints and inputs from gui
        print('<: Test environment for Kubernetes for Terraform :>')
        print('-' * 25)
        print('Choises: ')
        print('-' * 25)
        print('1. Base environment \
            \n2.Writable hostpath \
            \n3. Managed identity \
            \n4. Service account \
            \n5. Scan files \
            \n6. Cleanup environment')
        choice = input(':> ')
        print(self.check_dependencies())
        print('dependencies checked')
        self.fetch_mainfest(choice)

def main():
    test = Main_Gui()
    test.gui()
     