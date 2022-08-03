#!/bin/sh
git clone https://github.com/prizoner627/dockersec.git
pip install -r requirements.txt
apt update
apt install nmap
chmod -R +x /dockersec