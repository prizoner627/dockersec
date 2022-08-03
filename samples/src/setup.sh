#!/bin/sh
git clone https://github.com/prizoner627/dockersec.git
apt update
apt install nmap
chmod -R +x dockersec/
cd dockersec/
pip install -r requirements.txt
