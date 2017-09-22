FROM python:2.7-slim

RUN apt-get update -qq && apt-get install -y git build-essential gcc

RUN pip install --upgrade pip
RUN git clone https://github.com/rednaga/yara-python.git
WORKDIR yara-python
RUN python setup.py install
RUN pip install apkid

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

ENTRYPOINT ["apkid"]
