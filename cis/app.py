#sudo pip3 install flask => to install outside the local directory, must include sudo
from flask import Flask, request, jsonify
from dockerfile_parse import DockerfileParser
from colorama import Fore, Style
from pprint import pprint

app = Flask(__name__)

@app.route('/', methods=['POST'])
def hello():

    #  curl -X POST http://127.0.0.1:5000/ -H 'Content-Type: application/json' -d '{"dockerfile":{ "fixedVersion":"latest","path":"/home/dush/dockersec/cis/samples/Dockerfile","version":"latest","image":"vulhub/node" }}'
    if request.method == 'POST':
        # modify docker file
        content = request.json
        # print(content["dockerfile"]["path"])

        dfp = DockerfileParser()

        # open dockerfile for read
        with open(content["dockerfile"]["path"], 'r+') as f1:
            data = f1.read()
            dfp.content = data
            # pprint(dfp.content)

            # creating backup file for write 
            backup_filepath = content["dockerfile"]["path"] + ".bak"

            with open(backup_filepath, 'w') as f2:
                f2.seek(0)
                f2.truncate() 
                f2.write(data)

            # writing data to original file
            if dfp.baseimage is not None:
                dfp.baseimage = content["dockerfile"]["image"] + ":" + content["dockerfile"]["fixedVersion"]
            f1.seek(0)
            f1.truncate()    
            f1.write(dfp.content)

        # modify composefile
        with open(content["composefile"]["path"], 'r+') as f3:
            data = f3.read()
            dfp.content = data
            a = dfp.structure        

            # creating backup file for write 
            backup_filepath = content["composefile"]["path"] + ".bak"

            with open(backup_filepath, 'w') as f4:
                f4.seek(0)
                f4.truncate() 
                f4.write(data) 

            # writing data to original file
        with open(content["composefile"]["path"], 'r+') as f5:    
            data = f5.read()
            dfp.content = data
            a = dfp.structure      
            
            for line in a:
                if line['instruction'] == 'IMAGE:':
                    # print(line['content'].split(":"))
                    baseImage = line['content']   
                    ins = baseImage.split(":")[0] + ":"
                    image = baseImage.split(":")[1]
                    latest = ":latest\n"
                    new = ins + image + latest
                    # print(new)
                    line['content'] = new
                    # print(line['content'])
                    # f5.write(line['content'])
                # f3.write(line['content'])

            f5.seek(0)
            f5.truncate() 

            for line in a:
                f5.write(line['content'])    

        return '<h1>Completed !</h1>'

@app.route('/about/')
def about():
    return '<h3>This is a Flask web application.</h3>'

if __name__ == "__main__":
    app.run(debug = True, port = 5000)    