
FROM ubuntu:latest

# Timezone is needed for installing uwsgi
ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir -p /app/cert

COPY av_gate.py av_gate.ini requirements.txt /app
COPY cert/* /app/cert
COPY docker/nginx.conf /etc/nginx/conf.d/av_gate.conf
COPY docker/uwsgi.ini /etc/uwsgi/apps-enabled/av_gate.ini

RUN apt update && apt install -y \
    nginx uwsgi uwsgi-plugin-python3 python3 python3-pip clamav clamav-daemon 
    
RUN pip3 install -r /app/requirements.txt

# starting services
# uncommon for docker, but this is for demonstration
# RUN service uwsgi start
# RUN service nginx start
RUN service clamav-daemon start

# init clamav database 
RUN freshclam

# expose not possible for ranges
expose 8400
expose 8401
