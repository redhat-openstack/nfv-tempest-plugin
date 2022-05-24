from oslo_log import log as logging
import re

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class CollectInfo():
    def get_osp_version():
        version_pattern = re.compile(r'\d+.\d+.\d+')
        with open('/etc/rhosp-release', 'r') as release:
            version = version_pattern.search(release.read())

        return version.group(0)
