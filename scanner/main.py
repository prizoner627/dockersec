import requests
import time
import click
import json
import xml.etree.ElementTree as ET
import subprocess

from json.decoder import JSONDecodeError
from bs4 import BeautifulSoup

@click.command()							
@click.argument('ip', type=str)

def main(ip):
    # Reading data from the xml file
    with open('nmap.xml', 'r') as f:
        data = f.read()
    
    # Passing the data of the xml
    # file to the xml parser of
    # beautifulsoup
    bs_data = BeautifulSoup(data, 'xml')
    # print(bs_data.prettify())

    #find port elements
    result = bs_data.find_all("port")
    # print(result)

    for item in result:
        # print(item.prettify())
        # print(item.find('service').find('cpe').contents)
        pid = item.get('portid')
        pro = item.get('protocol')
        state = item.find('state').get('state')
        product = item.find('service').get('product')
        version = item.find('service').get('version')

        #check type NONE
        if product is not None:
            #get vulenerabilities
            if version is None:
                arg = product
                out = subprocess.check_output(['python3','../vul/main.py', arg])
                output = out.decode("utf-8")
                print("Port {} | {} | {} | {} | {} \n".format(pid, pro, state, product, version ))
                print(output)
            else:
                arg = product + " " + version
                out = subprocess.check_output(['python3','../vul/main.py', arg])
                output = out.decode("utf-8")
                print("Port {} | {} | {} | {} |  {} \n".format(pid, pro, state, product, version ))
                print(output)
        else:
            print("No service detected \n")

if __name__ == '__main__':
    main()