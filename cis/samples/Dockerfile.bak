FROM vulhub/node:latest

RUN set -ex \
    && cd /usr/src \
    && npm install

WORKDIR /usr/src

CMD ["npm", "run", "start"]