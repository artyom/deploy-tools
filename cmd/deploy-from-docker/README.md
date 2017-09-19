`deploy-from-docker` is an experimental tool that allows creating configurations directly from the [docker image](https://github.com/moby/moby/blob/master/image/spec/v1.2.md).

This way container images can be built using docker, but deployed and run without docker involved at all.

Usage example:

	docker save alpine:latest | deploy-from-docker

This command would create a new configuration named `alpine.latest` (or update existing one).
