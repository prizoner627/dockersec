#sudo pip3 install flask => to install outside the local directory, must include sudo
from flask import Flask, request, jsonify
from dockerfile_parse import DockerfileParser
from colorama import Fore, Style

app = Flask(__name__)

@app.route('/', methods=['POST'])
def hello():

    #  curl -X POST http://127.0.0.1:5000/ -H 'Content-Type: application/json' -d '{"dockerfile":{ "path":"/home/dush/dockersec/cis/samples/Dockerfile","version":"latest","image":"vulhub/node" }}'
    if request.method == 'POST':
        # modify docker file
        content = request.json
        print(content["dockerfile"]["path"])

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
                dfp.baseimage = "vulhub/node:latest"
            f1.seek(0)
            f1.truncate()    
            f1.write(dfp.content)
            print(dfp.content)

        # modify composefile
        print(content["composefile"]["path"])

        with open(content["composefile"]["path"], 'r') as f:
            data = f.read()
            dfp.content = data
            a = dfp.structure        

            for line in a:
                if line['instruction'] == 'IMAGE:':
                    # print(line['content'].split(":"))
                    baseImage = line['content'].split(":")[1:3] 
                    image = baseImage[0].strip()
                    version = baseImage[1].strip()
                    print(image,version)
                    
        return '<h1>Hello, World!</h1>'


@app.route('/about/')
def about():
    return '<h3>This is a Flask web application.</h3>'

if __name__ == "__main__":
    app.run(debug = True, port = 5000)    