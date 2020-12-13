FROM centos/python-36-centos7

LABEL description="tempest with nfv-plugin for OpenStack Platform"
LABEL summary="tempest with nfv-plugin for OpenStack Platform"

USER default

RUN pip3 install --upgrade pip setuptools \
 && pip3 install tempest-nfv-plugin python-tempestconf python-openstackclient

RUN tempest init ~/tempest \
 && mkdir ~/tempest/container_tempest/

COPY tools/config_generate.sh /opt/app-root/src/tempest/config_generate.sh
RUN chmod +x /opt/app-root/src/tempest/config_generate.sh


WORKDIR /opt/app-root/src/tempest
