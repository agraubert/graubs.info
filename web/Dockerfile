FROM ubuntu:20.04
MAINTAINER Aaron Graubert

RUN apt-get update && apt-get upgrade -y && DEBIAN_FRONTEND=noninteractive apt-get install -y \
  software-properties-common build-essential python3 python3-pip

COPY requirements.txt /opt/graubs/

RUN python3 -m pip install --upgrade pip setuptools wheel && python3 -m pip install -r /opt/graubs/requirements.txt

COPY . /opt/graubs

CMD python3 -m opt.graubs.main
