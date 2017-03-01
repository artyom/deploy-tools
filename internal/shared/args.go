package shared

import (
	"strings"

	"github.com/pkg/errors"
)

// ArgsDelVersion describes arguments to delete version command
type ArgsDelVersion struct {
	Name    string `flag:"name,component name"`
	Version string `flag:"version,unique version id"`
}

// Validate checks arguments sanity
func (a *ArgsDelVersion) Validate() error {
	if a.Name == "" || a.Version == "" {
		return errors.New("both name and version should be set")
	}
	if strings.ContainsRune(a.Name, ':') {
		return errors.New("name cannot contain : symbol")
	}
	return nil
}

// ArgsDelComponent describes arguments to delete component command
type ArgsDelComponent struct {
	Name string `flag:"name,component name"`
}

// Validate checks arguments sanity
func (a *ArgsDelComponent) Validate() error {
	if a.Name == "" {
		return errors.New("name should be set")
	}
	return nil
}

// ArgsDelConfiguration describes arguments to delete configuration command
type ArgsDelConfiguration struct {
	Name  string `flag:"name,configuration name"`
	Force bool   `flag:"force,remove configuration for real"`
}

// Validate checks arguments sanity
func (a *ArgsDelConfiguration) Validate() error {
	if a.Name == "" {
		return errors.New("name should be set")
	}
	if strings.ContainsRune(a.Name, '/') {
		return errors.New("name cannot contain / symbol")
	}
	return nil
}

// ArgsAddConfiguration describes arguments to configuratin add command
type ArgsAddConfiguration struct {
	Name   string       `flag:"name,configuration name"`
	Layers compVerSlice `flag:"layer,layer in component:version format; can be set multiple times"`
}

// Validate checks arguments sanity
func (a *ArgsAddConfiguration) Validate() error {
	if a.Name == "" {
		return errors.New("name should be set")
	}
	if len(a.Layers) == 0 {
		return errors.New("configuration should have at least one layer")
	}
	if strings.ContainsRune(a.Name, '/') {
		return errors.New("name cannot contain / symbol")
	}
	return nil
}

// ArgsUpdateConfiguration describes update configuration command arguments
type ArgsUpdateConfiguration struct {
	Name string `flag:"name,configuration name"`
	Comp string `flag:"component,component name to update"`
	Ver  string `flag:"version,new version of selected component"`
}

// Validate checks arguments sanity
func (a *ArgsUpdateConfiguration) Validate() error {
	if a.Name == "" || a.Comp == "" || a.Ver == "" {
		return errors.New("name, component and version should all be set")
	}
	if strings.ContainsRune(a.Name, '/') {
		return errors.New("name cannot contain / symbol")
	}
	return nil
}

// ArgsBumpConfiguration describes arguments for command to update single
// configuration layer to its most recent version
type ArgsBumpConfiguration struct {
	Name string `flag:"name,configuration name"`
	Comp string `flag:"component,component name to update"`
}

// Validate checks arguments sanity
func (a *ArgsBumpConfiguration) Validate() error {
	if a.Name == "" || a.Comp == "" {
		return errors.New("both name and component should be set")
	}
	if strings.ContainsRune(a.Name, '/') {
		return errors.New("name cannot contain / symbol")
	}
	return nil
}

// ArgsShowConfiguration describes show configuration command arguments
type ArgsShowConfiguration struct {
	Name    string `flag:"name,configuration name"`
	Verbose bool   `flag:"v,show extra details"`
}

// Validate checks arguments sanity
func (a *ArgsShowConfiguration) Validate() error {
	if a.Name == "" {
		return errors.New("name should be set")
	}
	if strings.ContainsRune(a.Name, '/') {
		return errors.New("name cannot contain / symbol")
	}
	return nil
}

// ArgsShowComponent describes show component command arguments
type ArgsShowComponent struct {
	Name string `flag:"name,component name"`
}

// Validate checks arguments sanity
func (a *ArgsShowComponent) Validate() error {
	if a.Name == "" {
		return errors.New("name should be set")
	}
	if strings.ContainsRune(a.Name, ':') {
		return errors.New("name cannot contain : symbol")
	}
	return nil
}

// ArgsAddVersionByHash describes arguments to add component version command
// when version is added by its hash from previously downloaded file
type ArgsAddVersionByHash struct {
	Name    string `flag:"name,component name"`
	Version string `flag:"version,unique version id"`
	Hash    string `flag:"hash,sha256 content hash in hex representation (64 chars)"`
}

// Validate checks arguments sanity
func (a *ArgsAddVersionByHash) Validate() error {
	if a.Name == "" || a.Version == "" || a.Hash == "" {
		return errors.New("name, version and hash should all be set")
	}
	if strings.ContainsRune(a.Name, ':') {
		return errors.New("name cannot contain : symbol")
	}
	if len(a.Hash) != 64 {
		return errors.New("hash should be a hex representation of content sha256 sum, 64 chars long")
	}
	return nil
}

// ArgsAddVersionByFile describes arguments to add component version command
// when version is added by uploading file
type ArgsAddVersionByFile struct {
	Name    string `flag:"name,component name"`
	Version string `flag:"version,unique version id"`
	File    string `flag:"file,tar.gz file to upload"`
}

// Validate checks arguments sanity
func (a *ArgsAddVersionByFile) Validate() error {
	if a.Name == "" || a.Version == "" || a.File == "" {
		return errors.New("name, version and file should all be set")
	}
	if strings.ContainsRune(a.Name, ':') {
		return errors.New("name cannot contain : symbol")
	}
	return nil
}

// compVer holds single layer specification as passed by operator
type compVer struct {
	Comp, Ver string
}

// compVerSlice implements flag.Value interface
type compVerSlice []compVer

func (c *compVerSlice) String() string { return "" }
func (c *compVerSlice) Set(value string) error {
	flds := strings.SplitN(value, ":", 2)
	if len(flds) != 2 {
		return errors.New("invalid value")
	}
	for _, v := range *c {
		// XXX: this may not the best way to check for dupes, but
		// normally number of layers is expected to be small, so leave
		// this as is for now
		if v.Comp == flds[0] {
			return errors.Errorf("duplicate component %q", flds[0])
		}
	}
	*c = append(*c, compVer{Comp: flds[0], Ver: flds[1]})
	return nil
}

// CommandsListing is used to print listing of all supported commands with their
// short description
const CommandsListing = `
addver          add new component version from previously uploaded file
addconf         add new configuration from existing component versions
bumpconf        update single layer of configuration to most recent uploaded version
changeconf      update single layer of configuration to specifig version
showconf        show configuration
showcomp        show component versions
components      list all known components
configurations  list all known configurations
delver          delete component version
delcomp         delete all component versions
delconf         delete configuration

use -h flag to get more help on a specific command
`
