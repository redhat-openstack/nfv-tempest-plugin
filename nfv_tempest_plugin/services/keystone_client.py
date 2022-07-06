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

        if cls.uc_server_client == 'nova':
            undercloud_rc = cls.parse_rc_file(
                CONF.nfv_plugin_options.undercloud_rc_file)

            cls.undercloud_keystone_session = session.Session(auth=v3.Password(
                auth_url=undercloud_rc['OS_AUTH_URL'],
                username=undercloud_rc['OS_USERNAME'],
                password=undercloud_rc['OS_PASSWORD'],
                project_name=undercloud_rc['OS_PROJECT_NAME'],
                user_domain_name=undercloud_rc['OS_USER_DOMAIN_NAME'],
                project_domain_name=undercloud_rc[
                    'OS_PROJECT_DOMAIN_NAME']), verify=False)
        else:
            cls.undercloud_keystone_session = openstack.connect(
                cloud='undercloud', verify=False)

        cls.overcloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=CONF.identity.uri,
            username=CONF.auth.admin_username,
            password=CONF.auth.admin_password,
            project_name=CONF.auth.admin_project_name,
            user_domain_name=CONF.auth.admin_domain_name,
            project_domain_name=CONF.auth.admin_domain_name), verify=False)

    @classmethod
    def parse_rc_file(cls, rc_file):
        """Parse rc file

        Parse rc file and take OSP related variables

        :param rc_file: path to the rc file
        :type rc_file: string
        """
        config = {}
        try:
            with open(rc_file, 'r') as rc:
                for line in rc.read().split('\n'):
                    if 'export OS_' in line:
                        param = line.split('=')
                        config[param[0].replace('export ', '')] = \
                            param[1].replace('\'', '')
        except Exception as err:
            LOG.info('The following exceptions occurred while trying '
                     'to parse rc file {}'.format(err))
            raise err

        return config
