# OS
FROM ubuntu:18.04

USER root
WORKDIR /root

RUN sed -i.bak -e "s%http://archive.ubuntu.com/ubuntu/%http://ftp.jaist.ac.jp/pub/Linux/ubuntu/%g" /etc/apt/sources.list

ENV DEBIAN_FRONTEND=noninteractive

# Initialization
RUN apt -y update && apt -y upgrade

# install packages
RUN apt install -y locales && LANG=ja_JP.UTF-8 && locale-gen ja_JP.UTF-8 && echo "export LANG=ja_JP.UTF-8" >> /etc/bash.bashrc && \
    apt install -y apt-utils && \
    apt install -y sudo && \
    apt install -y \
        wget curl git software-properties-common lsof \
        make build-essential cmake m4 libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
        llvm libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev \
        emacs python tmux

# install SEAL
ARG SEAL_TARGET_VERSION="3.3.1"

WORKDIR /usr/local/src
RUN git clone https://github.com/Microsoft/SEAL.git && \
    cd SEAL/ && \
    git checkout ${SEAL_TARGET_VERSION} && \
    mkdir native/src/build && \
    cd native/src/build &&\
    cmake ../ && make -j4 && make install

# add user
ARG USER_NAME="user"

RUN adduser ${USER_NAME} && \
    usermod -aG sudo ${USER_NAME} && \
    echo "${USER_NAME}:hogehoge" | chpasswd && \
    echo "Defaults visiblepw" >> /etc/sudoers
# # sudo password is not required.
# RUN echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER ${USER_NAME}
WORKDIR /home/${USER_NAME}

RUN echo -e "\nexport TZ=Asia/Tokyo" >> ~/.bashrc

# # pyenv
# RUN git clone https://github.com/pyenv/pyenv.git ~/.pyenv

# RUN echo "" >> ~/.bashrc && \
#     echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc && \
#     echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc && \
#     bash -c 'echo -e "if command -v pyenv 1>/dev/null 2>&1; then\n  eval \"\$(pyenv init -)\"\nfi" >> ~/.bashrc'

# ENV HOME /home/test
# ENV PYENV_ROOT $HOME/.pyenv
# ENV PATH $PYENV_ROOT/bin:$PATH
# RUN eval "$(pyenv init -)" && \
#     pyenv install 3.7.3



