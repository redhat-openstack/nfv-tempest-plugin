1. Get podman  or docker for you distribution from: [podman installation guide](https://podman.io/getting-started/installation) or [docker installation guide](https://docs.docker.com/get-docker/)  
**NOTE:** you can switch all podman CLI commands in this guide to docker comands  
2. Git clone nfv-tempest-plugin
3. Build container:   
`podman build . --tag quay.io/rhos-dfg-nfv/tempest-nfv-plugin:<version>`
4. push container to docker hub:  
`podman login quay.io`  
`podman push quay.io/rhos-dfg-nfv/tempest-nfv-plugin:<version>`

 

