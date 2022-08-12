FROM vulhub/node:8.5.0

RUN set -ex \
    && cd /usr/src \
    && npm install

WORKDIR /usr/src

CMD ["npm", "run", "start"]