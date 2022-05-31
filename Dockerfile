
FROM ubuntu:latest

# Timezone is needed for installing uwsgi
ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get -y update \
&& apt-get -y install nginx uwsgi uwsgi-plugin-python3 python3 python3-pip clamav clamav-daemon 

# remove config for group on socket clamd    
RUN sed -i '/^LocalSocketGroup .*$/d' /etc/clamav/clamd.conf

COPY cert/* /app/cert/
COPY replacements/* /app/replacements/
COPY docker/startup.sh /bin/
COPY docker/nginx.conf /etc/nginx/conf.d/av_gate.conf
COPY docker/uwsgi.ini /etc/uwsgi/apps-enabled/av_gate.ini
# copy initial clamav signatures to avoid cooldown
COPY docker/clamav/* /var/lib/clamav

COPY av_gate.py requirements.txt /app/
COPY docker/av_gate.ini /app/
RUN pip3 install -r /app/requirements.txt

ENTRYPOINT "/bin/startup.sh"

# expose not possible for ranges
EXPOSE 8400
EXPOSE 8401
