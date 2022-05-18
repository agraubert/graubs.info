FROM ubuntu:20.04
MAINTAINER Aaron Graubert

RUN apt-get update && apt-get upgrade -y && DEBIAN_FRONTEND=noninteractive apt-get install -y \
  software-properties-common build-essential python3 python3-pip python3-virtualenv

COPY . /opt/graubs

RUN python3 -m virtualenv /opt/graubs/.env && . /opt/graubs/.env/bin/activate && python -m pip install --upgrade pip setuptools wheel && \
  pip install -r /opt/graubs/requirements.txt

RUN echo ". /opt/graubs/.env/bin/activate" >> /root/.bashrc && chmod 755 /root/.bashrc

CMD bash -c ". /opt/graubs/.env/bin/activate && python -m opt.graubs.main"
