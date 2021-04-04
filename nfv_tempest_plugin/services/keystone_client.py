
from envbash import load_envbash
from keystoneauth1.identity import v3
from keystoneauth1 import session
from os import environ
from tempest import config


CONF = config.CONF


class KeystoneClient():
    @classmethod
    def set_keystone_clients(cls):
        load_envbash(
            CONF.nfv_plugin_options.undercloud_rc_file)

        cls.undercloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=environ['OS_AUTH_URL'],
            username=environ['OS_USERNAME'],
            password=environ['OS_PASSWORD'],
            project_name=environ['OS_PROJECT_NAME'],
            user_domain_name=environ[
                'OS_USER_DOMAIN_NAME'],
            project_domain_name=environ[
                'OS_PROJECT_DOMAIN_NAME']), verify=False)

        cls.overcloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=CONF.identity.uri,
            username=CONF.auth.admin_username,
            password=CONF.auth.admin_password,
            project_name=CONF.auth.admin_project_name,
            user_domain_name=CONF.auth.admin_domain_name,
            project_domain_name=CONF.auth.admin_domain_name), verify=False)
