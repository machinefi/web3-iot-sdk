# Base image which contains global dependencies
FROM ubuntu:22.04 as base
WORKDIR /workdir

# System dependencies
ARG arch=amd64
RUN mkdir /workdir/project
RUN mkdir /workdir/.cache
RUN apt-get -y update
RUN apt-get -y upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install \
    python3-pip \
    ninja-build \
    gperf \
    git \
    unzip \
    python3-setuptools \
    gdb \
    curl \
    lsb-release \
    psmisc \
    doxygen 

RUN apt-get -y clean && apt-get -y autoremove

RUN python3 -m pip install -U pip
RUN python3 -m pip install -U six cmake>=3.20.0 wheel setuptools
RUN apt-get -y install clang-format

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV XDG_CACHE_HOME=/workdir/.cache
