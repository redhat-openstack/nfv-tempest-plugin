### nfv-tempest-plugin

This project is a plugin to [OpenStack's tempest](https://github.com/openstack/tempest) used to test NFV usecases.

### Advanded features used in this plugin

#### Nova

##### Microversions

OpenStack APIs are divided into two categories, major and minor.
Major versions are represented for example as identity v2, identity v3 or etc.
Minor versions are referred as microversions, they're dynamic and each one of them adds/deprecates fea
tures - used for backwards compatability.

The default Nova microversion is 2.1.

In this plugin we may use more advanced microversions in order to utilize advanced features or depreca
ted features.

Refer to [OpenStack's official Nova documentation regarding microversions](https://docs.openstack.org/nova/latest/contributor/microversions.html)

Refer to [OpenStack's official Nova documentation regarding API microversions](https://docs.openstack.org/nova/latest/reference/api-microversion-history.html)

##### Live Migration
OpenStack has the ability to migrate virtual machine from one OpenStack compute host to other OpenStack Compute host.

In this plugin we have a test which checks this feature.

Refer to [OpenStack's official documentation regarding live migration](https://docs.openstack.org/nova/latest/admin/configuring-migrations.html#section-configuring-compute-migrations).

### Installation

Please refer to the following [page](https://github.com/redhat-openstack/nfv-tempest-plugin/blob/master/docs/installation.md).

### Pre-requisites before running the plugin

Please refer to the following [page](https://github.com/redhat-openstack/nfv-tempest-plugin/blob/master/docs/tests_prerequisites_config.md).

### Tests and samples

For the list of tests with description, please refer to the following [page](https://github.com/redhat-openstack/nfv-tempest-plugin/blob/master/docs/tests.md).

For a sample external configuration file, please refer to the following [page](https://github.com/redhat-openstack/nfv-tempest-plugin/blob/master/docs/tests_config.yml.sample).

### Contributing

Please referr to the following [page](https://github.com/redhat-openstack/nfv-tempest-plugin/blob/master/docs/contribution.md).
