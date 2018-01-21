FROM node:7.3-alpine
MAINTAINER Candid Dauth <cdauth@cdauth.eu>

CMD npm start
EXPOSE 8888

RUN apk --no-cache add git openjdk8-jre gnupg

RUN adduser -D -h /opt/gnewpg -s /bin/bash gnewpg

WORKDIR /opt/gnewpg

COPY ./ ./

RUN chown -R gnewpg:gnewpg /opt/gnewpg

USER gnewpg

RUN npm install

USER root
RUN chown -R root:root /opt/gnewpg

USER gnewpg
