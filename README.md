# Deploy tools

This repository holds set of tools to automate file deployments:

* [deploy-registry](#deploy-registry) — server storing files and required metadata;
* [deploy-agent](#deploy-agent) — agent program running on server(s) and tracking single configuration against registry;
* [deployctl](#deployctl) — tool to manage state of configurations stored in registry and uploading files to it;
* [deploy-from-docker](https://github.com/artyom/deploy-tools/blob/master/cmd/deploy-from-docker/README.md) — an **experimental** tool that allows creating configurations directly from the docker images.

## Key concepts

Registry holds different *configurations*, each configuration usually corresponds to some project that needs to be deployed. On its target server each project is just a filesystem tree. Each configuration may include one or more *layers* — filesystem trees that are merged together to form a resulting configuration state. Each layer is a distinct *version* of a single *component*.

Consider the following example:

	service1:
		- code @ v001
		- configs @ abc123

Here **service1** is a *configuration* that is composed from two different *components*: **code** and **configs**. Each component may have multiple *versions* stored in registry, but single configuration only references concrete version of each component. So configuration is built from *layers*, which is particular *versions* of different *components*.

Data is uploaded to registry in form of `.tar.gz` archives holding files for particular version of single component; when consumer (deploy-agent) retrieves data for given configuration from registry, it unpacks each layer's `.tar.gz` file to the same directory, merging their contents.

## Install

[Go](https://golang.org/doc/install) is required to build this tools from source. Binary distributions are planned later.

	go get -u -v github.com/artyom/deploy-tools/cmd/...

This command would install 3 binaries: [deployctl](#deployctl), [deploy-registry](#deploy-registry), [deploy-agent](#deploy-agent)

## Registry setup

deploy-registry requires single directory to keep its files and state in (`-dir` flag), and two files of ssh `authorized_keys` format: one with operators' keys (`-opauth` flag), one with keys for servers/consumers (`-srvauth` flag). deploy-registry won't start unless each of these files have at least one key.

If directory (`-dir` flag) already contains `host_key` file, deploy-registry will try to parse it as pem-encoded ssh private key and use it as host key for built-in ssh server. If file is not found, new key would be generated and saved to this file. Key fingerprint is logged on deploy-registry start.

Commands to run deploy-registry locally:

	$ DIR=$HOME/deploy-registry
	$ mkdir $DIR
	$ cat $HOME/.ssh/id_rsa.pub | tee $DIR/operator.keys $DIR/service.keys
	$ deploy-registry -addr localhost:2022 -dir $DIR -opauth $DIR/operator.keys -srvauth $DIR/service.keys

## Managing registry

Running deploy-registry provides interface accessible via ssh/sftp protocols, so it can be used directly with ssh and sftp commands. deployctl program only provides a standalone shortcut.

Command `deployctl` understands two environment variables to set default registry address and host key fingerprint (copy/paste fingerprint that `deploy-registry` shows on its start):

	$ export DEPLOYCTL_ADDR=localhost:2022
	$ export DEPLOYCTL_FINGERPRINT=...

As an example, consider you want to deploy project what is built from single program and its configuration file:

	$ mkdir $HOME/project1
	$ echo "program body v1" >$HOME/project1/program.txt
	$ echo "config v1" >$HOME/project1/config.txt

Now create two different tar.gz archives, one for component **code**, one for component **config**:

	$ tar czf code_v1.tar.gz -C $HOME/project1 program.txt
	$ tar czf config_v1.tar.gz -C $HOME/project1 config.txt

Now upload both files to registry:

	$ echo "put code_v1.tar.gz" | sftp -P 2022 localhost
	$ echo "put config_v1.tar.gz" | sftp -P 2022 localhost

Both files are now uploaded, note that destination file name is not relevant — deploy-registry server automatically stores them to temporary files that can be referenced by their content hash, not name.

Now we should create new components from uploaded files — their sha256 hashes would be required for this:

	$ shasum -a 256 code_v1.tar.gz config_v1.tar.gz
	71915871fbd585ab18b94956ae8b5897adbd70df5d121c83f3d3a9b0f28830c0  code_v1.tar.gz
	cbccc5a8b69c622061628bd016d537aa40337a8de550f27a2012d5d634faf944  config_v1.tar.gz

Connect to deploy-registry server using standard ssh client:

	$ ssh -p 2022 localhost

When presented with `> ` prompt, enter the following commands to create two components:

	> addver -name code -version v01 -hash 71915871fbd585ab18b94956ae8b5897adbd70df5d121c83f3d3a9b0f28830c0
	> addver -name config -version v01 -hash cbccc5a8b69c622061628bd016d537aa40337a8de550f27a2012d5d634faf944

This created two different components: **code** and **config**, each of them now have single version. Command `components` shows all known components, command `showcomp` shows all versions of a single component:

	> showcomp -name config
	2017-03-01T11:23:36Z	v01

Now create new configuration **project1** consisting from both code and config components:

	> addconf -name project1 -layer code:v01 -layer config:v01

Notice how each `-layer` flag specifies both component name and its version, separated by colon.

Command `configurations` lists all known configurations, command `showconf` shows layers of specific configuration:

	> showconf -name project1
	code	v01	2017-03-01T11:28:18Z
	config	v01	2017-03-01T11:23:36Z

Now let's create update configuration to a new version:

	$ echo "config v2" >$HOME/project1/config.txt
	$ tar czf config_v2.tar.gz -C $HOME/project1 config.txt

Uploading versions and adding them manually as two steps may be inconvenient, so `deployctl` command can do this in one step:

	$ deployctl addver -name config -version v02 -file config_v2.tar.gz

Note how `deployctl` command arguments match deploy-registry console commands, except that `-hash` flag is replaced with `-file`.

Our **project1** configuration can now be updated to second version of configs. This can either be done using `deployctl`:

	$ deployctl changeconf -name project1 -component config -version v02

or deploy-registry console, available via ssh:

	$ ssh -p 2022 localhost
	> changeconf -name project1 -component config -version v02

## Tracking configurations and deployment

Configuration tracking and deployment is done by `deploy-agent`.

Program `deploy-agent` uses sftp interface to deploy-registry and can be explored manually using sftp client. `deploy-agent` uses user name **deploy-agent** and registry verifies its keys against public keys in separate file.

When user deploy-agent accesses registry via sftp protocol, it has access to two directories: **configs** which holds each known configuration in json format, and **files** that holds all components' files.

Our configuration specification can be downloaded using sftp command:

	$ sftp -P 2022 deploy-agent@localhost:configs/project1.json

Look at the file — notice how it contains metadata about each configuration layer and reference to file in `files` directory.

`deploy-agent` periodically polls registry server and detects updates in configuration it tracks. When changes are detected, it fetches all missing files, then creates new unique directory and unpacks each layer into this directory in the same order they are listed in configuration. After successfully unpacking data, it runs deploy script (`-script` flag) which is expected to do all custom actions like shutting down old service instance and start new, etc.

Script receives configuration state via the following environment variables:

* `OLDID` — unique id of old configuration (may be empty if there were no old configuration, i.e. first `deploy-agent` run);
* `OLDROOT` — path to directory where old configuration is unpacked (may be empty if there were no old configration);
* `NEWID` — unique id of new configuration;
* `NEWROOT` — path to directory where new configuration is unpacked;
* `STATEFILE` — path to temporary file with json representation of new configuration.


## Usage

### deploy-registry

	Usage of deploy-registry:
	  -addr string
		address to listen (default "localhost:2022")
	  -deadline duration
		max.lifetime of TCP connection (default 30m0s)
	  -dir string
		data directory (default "/var/lib/deploy-registry")
	  -maxver int
		max.number of component versions to keep (default 10)
	  -opauth string
		authorized_keys for operators (default "/etc/deploy-registry/operator.keys")
	  -srvauth string
		authorized_keys for services (default "/etc/deploy-registry/service.keys")

### deployctl

	Usage: deployctl [flags] subcommand [subcommand flags]
	  -addr string
		$DEPLOYCTL_ADDR, registry host address (host:port)
	  -fp string
		$DEPLOYCTL_FINGERPRINT, sha256 host key fingerprint (sha256:...)
	  -key string
		ssh private key to use; if not set, ssh-agent is used

	Subcommands:

	addver          add new component version from previously uploaded file
	addconf         add new configuration from existing component versions
	bumpconf        update single layer of configuration to most recent uploaded version
	changeconf      update single layer of configuration to specific version
	showconf        show configuration
	showcomp        show component versions
	components      list all known components
	configurations  list all known configurations
	delver          delete component version
	delcomp         delete all component versions
	delconf         delete configuration

	use -h flag to get more help on a specific command

### deploy-agent

	Usage of deploy-agent:
	  -addr string
		registry address (host:port) (default "localhost:2022")
	  -cleanold
		remove unreferenced unpacked files after successful switch
	  -dir string
		directory to store downloaded and unpacked files (default ".")
	  -fp string
		registry server key fingerprint
	  -key string
		ssh private key to use (default "id_ecdsa")
	  -name string
		configuration to track
	  -poll duration
		registry poll interval (default 30s)
	  -script string
		script to run on deploys (default "./deploy.sh")
	  -state string
		file to save state to (default "state.json")
	  -v	be more chatty about what's happening
