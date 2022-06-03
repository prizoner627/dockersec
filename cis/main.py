import requests
import time
import click
import json
import os
from json.decoder import JSONDecodeError
from subprocess import call

def check():
    #cleaning files
    if os.path.exists("./output.log.json"):
        os.remove("./output.log.json")
    if os.path.exists("./output.log"):
        os.remove("./output.log")

    rc = call("./main.sh", shell=True)
            

@click.command()							
@click.argument('keyword', type=str)
@click.option('--outfile', type=str, default="sample.txt", help='Output file name')

def main(keyword, outfile):
    check()

if __name__ == '__main__':
    main()