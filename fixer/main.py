
import click
from pprint import pprint
from dockerfile_parse import DockerfileParser

from json.decoder import JSONDecodeError
from bs4 import BeautifulSoup
import os 

@click.command()							
@click.option('--dockerfile', type=str, default="./samples/Dockerfile", help='Dockerfile location')
@click.option('--composefile', type=str, default="./samples/docker-compose3.yml", help='Docker-compose location')

def main(dockerfile,composefile):
    if composefile:
        scanComposeFile(composefile)  
         
    if dockerfile:
        scanDockerFile(dockerfile)

 

def easy(dockerfile):
    #open file for reading
    with open(dockerfile, 'r',encoding="utf-8") as f:
        lines = [(line) for line in f.readlines()]
        print(lines)
        print(lines[0].split()[1].split(":")[0] + ":latest")
        base  = lines[0].split()[1].split(":")[0] + ":latest\n"
        lines[0] = "FROM " + base

    with open('./Dockerfile', 'w',encoding="utf-8") as o:
        for line in lines:
            o.writelines(line)            

def new(dockerfile):
    #open file for reading
    with open(dockerfile, 'r') as f:
        lines = [(line) for line in f.readlines()]
        print(lines[0])
        dic = []
        cmds = ['FROM','LABEL','RUN','WORKDIR','CMD']

        for line,data in enumerate(lines):
            print(line,data.split())

            #handle empty lines
            if not data.split():
                # print("empty")
                print(line,data)

                x = {
                "instruction": "", 
                "sline":line, 
                "eline":line,
                "content":""
                }

                dic.insert(line,x)
            else:

                x = {
                    "instruction": "", 
                    "sline":0, 
                    "eline":0,
                    "content":""
                }

                dic.insert(line,x)
            # print(rows)

        pprint(dic)    

        # for line in lines:
        #     #select base image
        #     rows = line.split()

        #     print(rows,"rows")
        #     if not rows:
        #         print("empty")
        #     else:
        #         print(rows[0])
        #         if(rows[0] == 'FROM'):
        #             print("fpunid")
        #             baseimage = rows[1]
        #             print(baseimage) 
        #             setLatest = baseimage + ":latest"
        #             rows[1] = setLatest
        #             print(rows[1])
        #     # if line.split()[0] == 'FROM':
        # print(lines)        


    # #write to new  file
    # with open('./Dockerfile', 'w') as out:
    #     out.writelines(lines)

def scanDockerFile(dockerfile):
    print(dockerfile)
    dfp = DockerfileParser()

    #open file for reading
    with open(dockerfile, 'r') as f:
        # print(lines)
        data = f.read()
        dfp.content = data
        # pprint(dfp.content)

    if dfp.baseimage is not None:
        #scan base images for vulns
        # pprint(dfp.structure)
        #set baseimage to latest 
        baseimage = dfp.baseimage.split(":")
        setLatest = baseimage[0] + ":latest"
        print(setLatest,"latest")
        dfp.baseimage = setLatest 
        pprint(dfp.baseimage)
        pprint(dfp.content)
        p = dfp.content

        #write to new  file
    with open('./Dockerfile', 'w+') as out:
        out.write(p)
    


def scanComposeFile(composefile):
    print(composefile)
    dfp = DockerfileParser(False)

    # open file for reading
    with open(composefile, 'r') as f:
        data = f.read()
        dfp.content = data
        a = dfp.structure        

        for line in a:
            if line['instruction'] == 'IMAGE:':
                # print(line['value'])
                # baseImage = line['value']
                # image = baseImage.split(":")[0]
                # setLatest = image + ":latest"
                # line['value'] = setLatest
                # print(line['value'])
                #changing content
                print(line['content'].split(":"))
                baseImage = line['content']   
                ins = baseImage.split(":")[0] + ":"
                image = baseImage.split(":")[1]
                latest = ":latest\n"
                new = ins + image + latest
                print(new)
                line['content'] = new
                print(line['content'])

        for line in a:
            pprint(line['content'])
        
        #write to new  file
        with open('./docker-compose.yml', 'w') as out:
            for line in a:
                pprint(line['content'])
                out.write(line['content'])

    # this package creates a Dokcerfile by  default in the working directory.
    # so need to delete it manually.
    # os.remove("./Dockerfile")


if __name__ == '__main__':
    main()