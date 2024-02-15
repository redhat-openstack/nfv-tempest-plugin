from keystoneauth1.identity import v3
from keystoneauth1 import session
from nfv_tempest_plugin.tests.common.collect_info \
    import CollectInfo
import openstack
from oslo_log import log as logging
from tempest import config


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class KeystoneClient():
    @classmethod
    def set_keystone_clients(cls):
        cls.uc_server_client = CollectInfo.check_client()

        cls.overcloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=CONF.identity.uri,
            username=CONF.auth.admin_username,
            password=CONF.auth.admin_password,
            project_name=CONF.auth.admin_project_name,
            user_domain_name=CONF.auth.admin_domain_name,
            project_domain_name=CONF.auth.admin_domain_name), verify=False)

