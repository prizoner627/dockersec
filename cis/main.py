from time import clock_getres
import requests
import click
import json
import os
import nmap
from shutil import which
from pprint import pprint
from subprocess import call, DEVNULL
from bs4 import BeautifulSoup
from dockerfile_parse import DockerfileParser
import subprocess
from colorama import Fore, Style
import uuid

def cis_check():
    #cleaning files
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker CIS bechmarks check{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for dozens of common best-practices around deploying Docker containers in production.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Based on the CIS Docker Benchmark 1.3.1{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

    rc = call("./main.sh", shell=True)

def host_scan():
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker Host Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in host.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Running Port Scanner{Style.RESET_ALL}")
    
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1')

    results = []

    for port in nm['127.0.0.1']['tcp'].items():
        result = {
            "port" : port[0],
            "details": port[1],
        }

        results.append(result)
    
    # print(results)
    print(f"{Fore.YELLOW}[DEBUG] Found {len(results)} open ports{Style.RESET_ALL}")

    logdata = {}

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    logdata["hostscan"] = results

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

def scanDockerFile(dockerfile):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker File Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in DockerFile.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Scanning DockerFile{Style.RESET_ALL}")
    
    if os.path.exists(dockerfile):
        print(f"{Fore.YELLOW}[DEBUG] DockerFile found at {dockerfile}{Style.RESET_ALL}")
        dfp = DockerfileParser()

        #open file for reading
        print(f"{Fore.YELLOW}[DEBUG] Scanning DockerFile{Style.RESET_ALL}")
        with open(dockerfile, 'r') as f:
            data = f.read()
            dfp.content = data
            # pprint(dfp.content)

        if dfp.baseimage is not None:
            baseimage = dfp.baseimage.split(":")
            print(f"{Fore.YELLOW}[DEBUG] Found baseimage {baseimage}{Style.RESET_ALL}")

            logdata = {}

            with open("results/output.log.json","r") as logfile:
                logdata = json.load(logfile)

            d = {
                "location": dockerfile,
                "baseimage": baseimage
            }

            logdata["dockerfile"] = d

            with open("results/output.log.json","w") as logfile:
                print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
                json.dump(logdata, logfile, ensure_ascii=False, indent=4)
        else:
            (f"{Fore.YELLOW}[DEBUG] No baseimage found{Style.RESET_ALL}")    
    else:
        print(f"{Fore.YELLOW}[DEBUG] DockerFile not found{Style.RESET_ALL}")

def scanComposeFile(composefile):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Composefile File Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in Composefile.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Scanning Composefile{Style.RESET_ALL}")
    
    if os.path.exists(composefile):
        print(f"{Fore.YELLOW}[DEBUG] Composefile found at {composefile}{Style.RESET_ALL}")
        dfp = DockerfileParser(False)

        # open file for reading
        print(f"{Fore.YELLOW}[DEBUG] Scanning Composefile{Style.RESET_ALL}")
        with open(composefile, 'r') as f:
            data = f.read()
            dfp.content = data
            a = dfp.structure        

            for line in a:
                if line['instruction'] == 'IMAGE:':
                    # print(line['content'].split(":"))
                    baseImage = line['content'].split(":")[1:3] 
                    print(f"{Fore.YELLOW}[DEBUG] Found baseimage {baseImage}{Style.RESET_ALL}")

                    logdata = {}

                    with open("results/output.log.json","r") as logfile:
                        logdata = json.load(logfile)

                    d = {
                        "location": composefile,
                        "baseimage": baseImage
                    }

                    logdata["composefile"] = d

                    with open("results/output.log.json","w") as logfile:
                        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
                        json.dump(logdata, logfile, ensure_ascii=False, indent=4)
        
    else:
        print(f"{Fore.YELLOW}[DEBUG] Composefile not found{Style.RESET_ALL}")


def finish(scanId):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Finishing Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for system information.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    
    logdata = {}

    info = subprocess.run(['lsb_release', '-a'], capture_output=True, text=True).stdout

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    d = {
        "scanId": str(scanId),
        "info": str(info)
    }

    logdata["info"] = d

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

    with open("results/output.log.json", "r") as logfile:
        data = json.loads(logfile.read())
        # print(data)
        
        url = 'http://192.168.82.241:5000/host-results'
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")

def container_scan(scanId):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Starting Container Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for container security.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    
    print(scanId)
    rc = call("./container.sh", shell=True)

    nm = nmap.PortScanner()
    nm.scan('127.0.0.1')

    results = []

    for port in nm['127.0.0.1']['tcp'].items():
        result = {
            "port" : port[0],
            "details": port[1],
        }

        results.append(result)
    
    # print(results)
    print(f"{Fore.YELLOW}[DEBUG] Found {len(results)} open ports{Style.RESET_ALL}")

    logdata = {}

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    logdata["containerscan"] = results

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

    with open("results/output.log.json", "r") as logfile:
        data = json.loads(logfile.read())
        # print(data)

        url = 'http://192.168.82.241:5000/container-results'
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")    

@click.command()							
@click.argument('mode', type=str)
@click.option('--scantype', type=str, help='Please mention scan type (host/container)')
@click.option('--scanId', type=str, help='Please mention scan id')
@click.option('--outfile', type=str, default="sample.txt", help='Output file name')
@click.option('--dockerfile', type=str, default="./samples/Dockerfile", help='Dockerfile location')
@click.option('--composefile', type=str, default="./samples/docker-compose3.yml", help='Docker-compose location')

def main(mode,scantype, outfile,dockerfile,composefile):
    print(f"{Fore.GREEN}\n# DockySec v1.0 \n{Style.RESET_ALL}")

    if which("nmap") is None:
        print(f"{Fore.RED}[IMPORTANT] Nmap is not installed{Style.RESET_ALL}")
        exit()
        # print(f"{Fore.YELLOW}[DEBUG] Installing nmap \n{Style.RESET_ALL}")
        # call('sudo apt install --no-install-recommends -y nmap', shell=True, stdout=DEVNULL, stderr=DEVNULL)


    #set permissions on results folder
    subprocess.call(['chmod', '+xrw', 'results/'])

    if mode == 'scan':
        if scantype == "host":
            scanId = uuid.uuid4()
            print(f"{Fore.RED}[IMPORTANT] Please remember this scan id to run container specific scans {scanId}{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans \n{Style.RESET_ALL}")
            if os.path.exists("./results/output.log.json"):
                os.remove("results/output.log.json")
            if os.path.exists("results/output.log"):
                os.remove("results/output.log")

            cis_check()
            host_scan()
            scanDockerFile(dockerfile)
            scanComposeFile(composefile)
            finish(scanId)
            
        if scantype == "container":
            if not scanId:
                print(f"{Fore.RED}[ERROR] Please define scanId{Style.RESET_ALL}")
                exit() 
            else:    
                print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans \n{Style.RESET_ALL}")
                if os.path.exists("./results/output.log.json"):
                    os.remove("results/output.log.json")
                if os.path.exists("results/output.log"):
                    os.remove("results/output.log")

                container_scan(scanId)

        if not scantype:
            print(f"{Fore.RED}[ERROR] Please define scantype{Style.RESET_ALL}")

    if mode == 'fix':
        print("fix")    

if __name__ == '__main__':
    main()


