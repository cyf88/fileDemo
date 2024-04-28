FROM ubuntu:22.04

EXPOSE 8000/tcp

RUN apt-get update && \
        DEBIAN_FRONTEND="noninteractive" \
        apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ca-certificates \
        git && \
        apt-get autoremove -y && \
        apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/sign

WORKDIR /opt/sign
RUN git clone --depth=1 https://github.com/cyf88/fileDemo.git && \
    cd fileDemo && \
    mkdir -p build

WORKDIR /opt/sign/fileDemo/build
RUN cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make
RUN cp test/test /usr/local/bin/ && \
    cp sdk/libsdk.so /usr/local/lib/ && \

ENV PATH /usr/local/lib/:$PATH
CMD ["/usr/local/bin/test"]
