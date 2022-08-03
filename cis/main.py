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
from http.server import BaseHTTPRequestHandler, HTTPServer
from requests import get
import app

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

    if "tcp" in nm['127.0.0.1']:
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
        path = os.path.abspath(dockerfile)

        print(f"{Fore.YELLOW}[DEBUG] DockerFile found at {path}{Style.RESET_ALL}")
        dfp = DockerfileParser()

        #open file for reading
        print(f"{Fore.YELLOW}[DEBUG] Scanning DockerFile{Style.RESET_ALL}")
        with open(dockerfile, 'r') as f:
            data = f.read()
            dfp.content = data
            # pprint(dfp.content)

        if dfp.baseimage is not None:
            baseimage = dfp.baseimage.split(":")

            image = baseimage[0].strip()
            version = baseimage[1].strip()

            print(f"{Fore.YELLOW}[DEBUG] Found baseimage {image} : {version}{Style.RESET_ALL}")

            logdata = {}

            with open("results/output.log.json","r") as logfile:
                logdata = json.load(logfile)

            d = {
                "path": path,
                "location": dockerfile,
                "baseimage": baseimage,
                "image": image,
                "version":version
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
        path = os.path.abspath(composefile)

        print(f"{Fore.YELLOW}[DEBUG] Composefile found at {path}{Style.RESET_ALL}")
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

                    image = baseImage[0].strip()
                    version = baseImage[1].strip()

                    print(f"{Fore.YELLOW}[DEBUG] Found baseimage {image} : {version}{Style.RESET_ALL}")

                    logdata = {}

                    with open("results/output.log.json","r") as logfile:
                        logdata = json.load(logfile)

                    d = {
                        "path": path,
                        "location": composefile,
                        "baseimage": baseImage,
                        "image": image,
                        "version":version,
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
    
    ip = get('https://api.ipify.org').content.decode('utf8')
    print('Public IP address is: {}'.format(ip))

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    d = {
        "scanId": str(scanId),
        "info": str(info),
        "ip": str(ip),
    }

    logdata["info"] = d

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

    with open("results/output.log.json", "r") as logfile:
        data = json.loads(logfile.read())
        # print(data)
        
        url = 'http://192.168.8.100:5000/host-results'
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")

def container_scan(scanid):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Starting Container Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for container security.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    
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

        url = 'http://192.168.82.241:5000/container-results?id=' + scanid
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")    

@click.command()							
@click.argument('mode', type=str)
@click.option('--scantype', type=str, help='Please mention scan type (host/container)')
@click.option('--scanid', type=str, help='Please mention scan id')
@click.option('--outfile', type=str, default="sample.txt", help='Output file name')
@click.option('--dockerfile', type=str, default="./samples/Dockerfile", help='Dockerfile location')
@click.option('--composefile', type=str, default="./samples/docker-compose3.yml", help='Docker-compose location')

def main(mode,scantype, outfile,dockerfile,composefile,scanid):
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
            sid = uuid.uuid4()

            print(f"{Fore.RED}[IMPORTANT] Please remember this scan id to run container specific scans {sid}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans \n{Style.RESET_ALL}")

            if os.path.exists("./results/output.log.json"):
                os.remove("results/output.log.json")
            if os.path.exists("results/output.log"):
                os.remove("results/output.log")

            cis_check()
            host_scan()
            scanDockerFile(dockerfile)
            scanComposeFile(composefile)
            finish(sid)
            
        if scantype == "container":
            if not scanid:
                print(f"{Fore.RED}[ERROR] Please define scanId{Style.RESET_ALL}")
                exit() 
            else:    
                print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans {Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[DEBUG] Using Scan ID {scanid} {Style.RESET_ALL}")

                if os.path.exists("./results/output.log.json"):
                    os.remove("results/output.log.json")
                if os.path.exists("results/output.log"):
                    os.remove("results/output.log")

                container_scan(scanid)

        if not scantype:
            print(f"{Fore.RED}[ERROR] Please define scantype{Style.RESET_ALL}")

    if mode == 'fix':
        print("fix")    

        # app.run(host='0.0.0.0', port=5000, debug=True)
        # hostName = "localhost"
        # serverPort = 8080
        # subprocess.call(['python3','-m','venv','venv'])
        # subprocess.call(['source','venv/bin/activate'])
        # subprocess.call(['flask','run'])
        # os.system("python app.py")
        subprocess.call(['flask','run'])
        # class MyServer(BaseHTTPRequestHandler):
        #     def do_GET(self):
        #         self.send_response(200)
        #         self.send_header("Content-type", "text/html")
        #         self.end_headers()
        #         self.wfile.write(bytes("<html><head><title>https://pythonbasics.org</title></head>", "utf-8"))
        #         self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
        #         self.wfile.write(bytes("<body>", "utf-8"))
        #         self.wfile.write(bytes("<p>This is an example web server.</p>", "utf-8"))
        #         self.wfile.write(bytes("</body></html>", "utf-8"))

        #     def do_POST(self):
        #         self.send_response(200)
        #         self.send_header('Content-type','text/html')
        #         self.end_headers()

        #         message = "Hello, World! Here is a POST response"
        #         self.wfile.write(bytes(message, "utf8"))    

        # webServer = HTTPServer((hostName, serverPort), MyServer)
        # print("Server started http://%s:%s" % (hostName, serverPort))

        # try:
        #     webServer.serve_forever()
        # except KeyboardInterrupt:
        #     pass

        # webServer.server_close()
        # print("Server stopped.")


if __name__ == '__main__':
    main()


