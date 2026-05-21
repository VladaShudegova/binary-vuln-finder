FROM --platform=linux/amd64 ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang-10 \
    gcc-multilib \
    g++-multilib \
    make \
    git \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir angr claripy networkx

WORKDIR /analyzer
