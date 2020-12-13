1. Get podman for you distrebution from: [podman installation guide](https://podman.io/getting-started/installation)
2. Git clone nfv-tempest-plugin
3. Build container:  
`podman build . --tag docker.io/nfvtempest/nfv-tempest:<version>`
4. push container to docker hub:  
`podman login docker.io`  
`podman push docker.io/nfvtempest/nfv-tempest:<version>`

 

