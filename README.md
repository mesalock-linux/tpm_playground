# TPM Playground

## Build and Run the Docker Image
```
# Build docker image
python docker/build.py
# Run docker image
docker run --name tpmplay -it -v`pwd`:/${HOME}/tpm tpm_playground /bin/bash
# inside docker, setup mock tpm environment
cd ${HOME}/tpm && sudo setup_mock_tpm.sh
```

## Cacheable Attestation
```
# start ttp server
docker exec -it tpmplay /bin/bash -c "cd ${HOME}/tpm/cache_attest && sudo ./run_ttp.sh"

# start worker server
docker exec -it tpmplay /bin/bash -c "cd ${HOME}/tpm/cache_attest && sudo ./run_workerserver.sh"

# request attestation
docker exec -it tpmplay /bin/bash -c "cd ${HOME}/tpm/cache_attest && python3 ./user.py"
```

