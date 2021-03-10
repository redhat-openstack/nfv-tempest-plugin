
from keystoneauth1.identity import v3
from keystoneauth1 import session
from oslo_log import log as logging
from tempest import config


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class KeystoneClient():
    def __init__(self):
        undercloud_rc = self.parse_rc_file(
            CONF.nfv_plugin_options.undercloud_rc_file)

        self.undercloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=undercloud_rc['OS_AUTH_URL'],
            username=undercloud_rc['OS_USERNAME'],
            password=undercloud_rc['OS_PASSWORD'],
            project_name=undercloud_rc['OS_PROJECT_NAME'],
            user_domain_name=undercloud_rc[
                'OS_USER_DOMAIN_NAME'],
            project_domain_name=undercloud_rc[
                'OS_PROJECT_DOMAIN_NAME']), verify=False)

        self.overcloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=CONF.identity.uri,
            username=CONF.auth.admin_username,
            password=CONF.auth.admin_password,
            project_name=CONF.auth.admin_project_name,
            user_domain_name=CONF.auth.admin_domain_name,
            project_domain_name=CONF.auth.admin_domain_name), verify=False)

    def parse_rc_file(self, rc_file):
        """parses standard rc file

        :param rcfile: path to rc file
        :return a dictionary that contains rc files vars as keys
        """
        conf = {}
        try:
            with open(rc_file, 'r') as rc:
                for line in rc.read().split('\n'):
                    if '=' in line:
                        param = line.split('=')
                        conf[param[0].replace('export ', '')] = \
                            param[1].replace('\'', '')
        except Exception as err:
            LOG.info('The following exception occured'
                     'while trying to parse rc file {}'.format(err))
            raise err

        return conf
