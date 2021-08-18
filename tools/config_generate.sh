# Set default values
default_input='tempest-deployer-input.conf'
default_additional_params=''

# Set variables value
deployer_input=${deployer_input:-$default_input}
additional_params=${additional_params:-$default_additional_params}

set -e
source container_tempest/overcloudrc

# Set optional params
network_param=""
if [[ ! -z "${external_network}" ]]; then
    network_param="--network-id `openstack network show ${external_network} -f value -c id`"
fi

image_param=""
if [[ ! -z "${image_name}" ]]; then
    image_param="--image container_tempest/${image_name}"
fi

flavor_param=""
if [[ ! -z "${flavor_name}" ]]; then
    flavor_param="compute.flavor_ref `openstack flavor show ${flavor_name} -c id -f value`"
fi

discover-tempest-config \
        --out etc/tempest.conf \
        --deployer-input container_tempest/$deployer_input \
        --debug --create \
        ${network_param} \
        ${image_param} \
        ${flavor_param} \
        $additional_params
