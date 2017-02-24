# Design of a deployment system

General overview: *configuration* corresponds to some project you'd want to deploy, this project may be composed from several *components*, each of them having multiple *versions*. Configuration then is an ordered list of concrete versions of different components. In context of configuration, concrete version of some component would be called *layer* below.

So, your project layout in this system may look like this:

	myProject (configuration):
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