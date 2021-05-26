FROM centos/python-36-centos7

LABEL description="tempest with nfv-plugin for OpenStack Platform"
LABEL summary="tempest with nfv-plugin for OpenStack Platform"

USER default

RUN pip3 install --upgrade pip setuptools \
 && pip3 install tempest-nfv-plugin python-tempestconf python-openstackclient neutron-tempest-plugin

RUN tempest init ~/tempest \
 && mkdir ~/tempest/container_tempest/

COPY tools/config_generate.sh /opt/app-root/src/tempest/config_generate.sh

# To have undercloud certificate used by python
RUN rm -f /opt/app-root/lib/python3.6/site-packages/certifi/cacert.pem \
 && ln -s  /etc/pki/ca-trust/source/anchors/undercloud-cacert.pem /opt/app-root/lib/python3.6/site-packages/certifi/cacert.pem

WORKDIR /opt/app-root/src/tempest
