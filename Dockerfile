FROM centos/python-36-centos7

LABEL description="tempest with nfv-plugin for OpenStack Platform"
LABEL summary="tempest with nfv-plugin for OpenStack Platform"

USER root

# Creation of user stack performed in order to use the "/home/stack" directory
# and aligned the use of "external_config_file" between containerized tempest
# and git based tempest.
# Remove once "external_config_file" will be removed from nfv tempest plugin.
RUN useradd -rm -d /home/stack stack \
 && chown default:default /home/stack

USER default

COPY ./ /opt/app-root/nfv-tempest-plugin

RUN pip3 install --no-cache-dir --upgrade pip setuptools \
 && pip3 install --no-cache-dir -e /opt/app-root/nfv-tempest-plugin \
 && pip3 install --no-cache-dir python-tempestconf python-openstackclient neutron-tempest-plugin

# To have undercloud certificate used by python
RUN rm -f /opt/app-root/lib/python3.6/site-packages/certifi/cacert.pem \
 && ln -s  /etc/pki/ca-trust/source/anchors/undercloud-cacert.pem /opt/app-root/lib/python3.6/site-packages/certifi/cacert.pem

RUN tempest init ~/tempest \
 && mkdir ~/tempest/container_tempest/ \
 && ln -s ~/tempest/container_tempest/ /home/stack/tempest

COPY tools/config_generate.sh /opt/app-root/src/tempest/config_generate.sh

WORKDIR /opt/app-root/src/tempest
