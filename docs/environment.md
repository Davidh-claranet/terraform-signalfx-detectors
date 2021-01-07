# Setup environment

To work with this repository, especially for developers, you will have to setup 
an environment based on [docker](https://www.docker.com/) to make available all 
dependencies and tools to perform usual automation to generate or update files in 
the repository.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
:link: **Contents**

- [Requirements](#requirements)
- [Usage](#usage)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Requirements

* `docker 17.06+` to run dev environment
* `make` to use Makefile

The dev environment uses the same [docker 
image](https://hub.docker.com/r/claranet/terraform-ci) as the CI. You still can install 
all dependencies listed in the 
[Dockerfile](https://github.com/claranet/dockerfiles/tree/master/terraform) directly on 
your host but it should be easier and less platform dependent with `docker`.

## Usage

To run the environment, be sure the docker daemon is running and run `make`:

```bash
$ systemctl start docker.service
$ make
docker exec -ti terraform-signalfx-detectors bash -i || \
        docker run --rm -ti -v "${PWD}:/work" \
                --name terraform-signalfx-detectors \
                claranet/terraform-ci:latest bash -i
Error: No such container: terraform-signalfx-detectors
[root@xxx work]# make
check      clean      detectors  dev        doc        gen        lint       module     outputs    readmes    stack      toc 
```

Now you can run every scripts directly or from `make` targets and enjoying automation.

You also can run "one shot" command directly using the docker image yourself to use a dependency 
not available on your host like `j2`:
```bash
$ docker run --rm -ti -v "${PWD}:/work" claranet/terraform-ci:latest make clean
git checkout -- examples/stack/detectors.tf
git clean -df modules/
```

CI and [Makefile](../Makefile) uses the `latest` tag which is not a good practice but 
avoid to update all references in case of "transparent" update (i.e. only update 
terraform to a newer minor version). The drawback is you could have to manually 
pull the latest image if your local one is too old:
```bash
$ docker pull docker pull claranet/terraform-ci
```

The best will be to use `--pull=always` policy directly in `docker run` command but 
this option is only available since docker version `>= 19.09` so we will wait before 
to use it in the `Makefile` but you can still use for "one shot" usage:
```bash
$ docker run --pull=always --rm -ti -v "${PWD}:/work" claranet/terraform-ci:latest make clean
```

