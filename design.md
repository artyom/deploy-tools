# Design of a deployment system

General overview: *configuration* corresponds to some project you'd want to deploy, this project may be composed from several *components*, each of them having multiple *versions*. Configuration then is an ordered list of concrete versions of different components. In context of configuration, concrete version of some component would be called *layer* below.

So, your project layout in this system may look like this:

	configurations:
		myProject:
			- (layer) codebase (component) @ (version) 123
			- (layer) configs (component) @ (version) v2
			- (layer) dataset (component) @ (version) xyz
	
	components:
		codebase:
			- (version) 123
			- (version) 345
		configs:
			- (version) v1
			- (version) v2
			- (version) v3
		dataset:
			- (version) abc
			- (version) xyz
		scripts:
			- (version) v1.0.0
			- (version) v1.0.1

In this example system holds 4 different components: codebase, configs, dataset, scripts. Each of these components have several different versions (each version holds blob representing component data at this version). Here system has single *configuration* named myProject, which consists of 3 *layers*: ordered list of concrete versions of distinct components. Notice that system may hold components not assigned to any configuration (here it's "scripts" component). Each component may also be included in multiple different configurations.

Each version in this system references a blob holding a set of files (tar.gz archive). As configuration consists of multiple ordered layers, each layer's data can be unpacked to the same directory, producing a merged file system tree.

Deploy system consists of 3 components:

- **deploy-registry**: this is a program running as a network service, it stores uploaded blobs and keeps track of all necessary metadata, configurations made, etc.;
- **deployctl**: this program is used by operators/scripts to interact with deploy-registry: create new components/versions, upload blobs, changing configurations;
- **deploy-agent**: this program is running on servers and tracks configuration of interest at deploy-registry; once configuration is updated, deploy-agent downloads missing layers to local cache, unpacks data to a new directory and runs a user-provided callback script which does necessary service restarts, notifications, etc.

## Examples of deployctl usage

Show known components:

	deployctl showcomp

Show known component versions:

	deployctl showcomp <component>

Upload new component version (components are created as necessary):

	deployctl addver <component:version> /path/to/file.tar.gz

Delete existing component version:

	deployctl delver <component:version>

Add new configuration — ordered layers (particular versions of different components):

	deployctl addconf <configuration> <component:version> [<component:version>...]

Change version of a single layer in existing configuration:

	deployctl changeconf <configuration> <component:version>

Change single layer in existing confguration to its most recent uploaded version:

	deployctl bumpconf <configuration> <component>

Replace existing configuration:

	deployctl replaceconf <configuration> <component:version> [<component:version>...]

Delete existing configuration:

	deployctl delconf <configuration>

Show configuration:

	deployctl showconf <configuration>

## Implementation details

Server (deploy-registry) uses SSH as its network protocol, reasons are following:

- built-in security & authentication;
- low key management overhead: operators already have ssh keys, keys can be added to (removed from) the system in a straightforward way (separate `authorized_keys` file);
- proper implementation would allow additional interface that could be managed with standard sftp/ssh commands w/o the need for deployctl;

### Interactions between deploy-registry and deployctl

File uploads are done using sftp subsystem, commands are executed using "regular" ssh subsystem. This would allow using this without deployctl at all if required, only using standard sftp/ssh commands.

Caveats: there should be a separate explicit step to submit hash of uploaded file to ensure it's been uploaded completely. How should uploaded file be tied to commands executed? Probably could be some auto-generated temporary name with following graceful period: client uploaded file is expected to issue command(s) referencing this file by its temporary name during grace period, otherwise uploaded file gets deleted.

Alternative: make it possible to reference file using hash scheme: i.e. in addition to `deployctl addver <component:version> /path/to/file.tar.gz` call make it possible to do `deployctl addver <component:version> sha256:...` which would reference previously uploaded file. In this case "manual" sftp/ssh workflow can be done like this:

	$ echo put file.tar.gz /tmp/upload | sftp registry.host

Server automatically calculates content hash as file is saved (**TODO**: check whether this is possible, since hashing works over io.Writer and [handling file saving requires io.WriterAt](https://godoc.org/github.com/pkg/sftp#FileWriter)).

	$ ssh registry.host deployctl addver component:version /tmp/upload

Here `/tmp/upload` is a temporary name valid only for current ssh session, so it can be any arbitrary name — server matches this name to real on-disk temporary file. Caveat: as this name is only valid during session, sftp call to upload file and following ssh call should be done over single ssh session, which is problematic when not using ssh master channels (they're *not* enabled by default).

As a workaround, client may reference uploaded file by its hash:

	$ ssh registry.host deployctl addver component:version sha256:${FILEHASH}

If provided hash matches one of uploaded file, it is moved to permanent location and new record is made. If provided hash matches one of the already tracked files, new record is made and temporary uploaded file is left untouched. If nothing matches provided hash, error is returned. Leftover temporary files are automatically removed after grace period.

### Interactions between deploy-registry and deploy-agent

Program deploy-agent would suffice sftp subsystem access only, as it only needs to fetch configuration metadata which can be represented as a virtual file, and corresponding data files can be fetched directly from disk.