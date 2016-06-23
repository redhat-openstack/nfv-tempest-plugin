Tempest Integration of NfvTest
==============================

This directory contains Tempest tests to cover the NfvTest project.

# Setup steps:
## Prerequisites:
* Installed tempest virtual environment.
* Cloned tempest repository.

## NFV plugin setup:

1. The tempeset-nfv-plugin repository should be cloned near to the main tempest directory.
* $ git clone https://review.gerrithub.io/redhat-openstack/tempest-nfv-plugin

2. Activate the tempest virtual env.
3. Browse to the nfv_tempest_plugin directory and install the nfv plugin:
* $ pip install --upgrade -e .

4. Test the installed plugin:
* $ pip list |grep -i nfv

5. Browse to the main tempest directory and check the newly installed nfv plugin:
* $ testr list-tests |grep -i nfv

