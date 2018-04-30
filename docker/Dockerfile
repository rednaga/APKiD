FROM python:2.7-slim

RUN apt-get update -qq && apt-get install -y git build-essential gcc pandoc

RUN pip install --upgrade pip
RUN git clone https://github.com/rednaga/yara-python.git
WORKDIR yara-python
RUN python setup.py install
RUN mkdir /apkid
COPY ./ /apkid/
WORKDIR /apkid
RUN pip install pypandoc
RUN python prep-release.py
RUN pip install -e .[dev]

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

ENTRYPOINT ["apkid"]
