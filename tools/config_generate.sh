# set default values
default_net='access'
default_flavor='nfv_qe_base_flavor'
default_input='tempest-deployer-input.conf'
default_image_name='rhel7.6'
default_additional_params=''

# set variables value
external_network=${external_network:-$default_net}
flavor=${flavor:-$default_flavor}
deployer_input=${deployer_input:-$default_input}
image_name=${image_name:-$default_image_name}
additional_params=${additional_params:-$default_additional_params}

set -e
source container_tempest/overcloudrc

discover-tempest-config \
	--out etc/tempest.conf \
	--deployer-input container_tempest/$deployer_input \
	--debug --create \
	--network-id `openstack network show $external_network -f value -c id` \
	compute.flavor_ref `openstack flavor show $flavor -c id -f value` \
	--image "container_tempest/$image_name" \
	$additional_params
