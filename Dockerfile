FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update  && apt-get upgrade -y && \
    apt-get -y install wget git cmake subversion build-essential libtool-bin python3-dev automake flex bison libglib2.0-dev libpixman-1-dev clang python3-setuptools llvm gcc-9-plugin-dev


RUN mkdir /work 
WORKDIR /work
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git aflpp-dev
RUN cd aflpp-dev && git checkout dev && make && make install

RUN git clone https://github.com/marekzmyslowski/libfiowrapper.git
WORKDIR /work/libfiowrapper
RUN make all

