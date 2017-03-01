// Command deployctl implements single-command operator's interface to manage
// deployments running under deploy-registry and deploy-agent
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/artyom/autoflags"
	"github.com/artyom/deploy-tools/internal/shared"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

func main() {
	args := &runArgs{
		Addr: os.Getenv("DEPLOYCTL_ADDR"),
		Fp:   os.Getenv("DEPLOYCTL_FINGERPRINT"),
	}
	fs := flag.NewFlagSet("deployctl", flag.ExitOnError)
	fs.Usage = usageFunc(fs.PrintDefaults)
	autoflags.DefineFlagSet(fs, args)
	fs.Parse(os.Args[1:])
	if err := args.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n\n", err)
		fs.Usage()
		os.Exit(2)
	}
	if len(fs.Args()) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := dispatch(args.Addr, args.Fp, fs.Args()); err != nil {
		if err == errFlagParseError {
			os.Exit(2)
		}
		if _, ok := err.(*ssh.ExitError); !ok { // don't write "Process exited with status 1"
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func dispatch(addr, fingerprint string, rawArgs []string) error {
	if len(rawArgs) == 0 {
		return errors.New("nothing to do")
	}
	cmd, args := rawArgs[0], rawArgs[1:]
	switch cmd {
	case "components", "configurations":
		return proxyCommand(addr, fingerprint, rawArgs)
	case "addver":
		val := &shared.ArgsAddVersionByFile{}
		if err := parseArgs(cmd, val, os.Stderr, args); err != nil {
			return err
		}
		return uploadAndUpdate(addr, fingerprint, val)
	}
	val, err := validatorForCommand(cmd)
	if err != nil {
		return err
	}
	if err := parseArgs(cmd, val, os.Stderr, args); err != nil {
		return err
	}
	return proxyCommand(addr, fingerprint, rawArgs)
}

func uploadAndUpdate(addr, fingerprint string, args *shared.ArgsAddVersionByFile) error {
	src, err := os.Open(args.File)
	if err != nil {
		return err
	}
	defer src.Close()
	client, cancel, err := dialSSH(addr, fingerprint)
	if err != nil {
		return err
	}
	defer cancel()
	sftpconn, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftpconn.Close()
	dst, err := sftpconn.Create("upload")
	if err != nil {
		return err
	}
	defer dst.Close()
	// TODO: check whether file is valid tar.gz archive by unpacking
	// & discarding it as we upload
	h := sha256.New()
	tr := io.TeeReader(src, h)
	if _, err := io.Copy(dst, tr); err != nil {
		return errors.WithMessage(err, "upload failure")
	}
	if err := dst.Close(); err != nil {
		return err
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	return session.Run(fmt.Sprintf("addver -name=%q -version=%q -hash=%x",
		args.Name, args.Version, h.Sum(nil)))
}

func dialSSH(addr, fingerprint string) (client *ssh.Client, closeFunc func(), err error) {
	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, nil, errors.WithMessage(err, "cannot connect to ssh-agent, check if SSH_AUTH_SOCK is set")
	}
	defer func() {
		if err != nil {
			agentConn.Close()
		}
	}()
	sshAgent := agent.NewClient(agentConn)
	var signers []ssh.Signer
	signers, err = sshAgent.Signers()
	if err != nil {
		return nil, nil, err
	}
	config := &ssh.ClientConfig{
		User:    os.Getenv("USER"),
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if hostFp := ssh.FingerprintSHA256(key); hostFp != fingerprint {
				return errors.Errorf("host key fingerprint mismatch: %v", hostFp)
			}
			return nil
		},
	}
	client, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	closeFunc = func() { client.Close(); agentConn.Close() }
	return client, closeFunc, nil
}

func proxyCommand(addr, fingerprint string, args []string) error {
	client, cancel, err := dialSSH(addr, fingerprint)
	if err != nil {
		return err
	}
	defer cancel()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	return session.Run(strings.Join(args, " "))
}

type validator interface {
	Validate() error
}

func validatorForCommand(name string) (validator, error) {
	v, ok := map[string]validator{
		"delver":     &shared.ArgsDelVersion{},
		"delcomp":    &shared.ArgsDelComponent{},
		"addconf":    &shared.ArgsAddConfiguration{},
		"delconf":    &shared.ArgsDelConfiguration{},
		"changeconf": &shared.ArgsUpdateConfiguration{},
		"showconf":   &shared.ArgsShowConfiguration{},
		"showcomp":   &shared.ArgsShowComponent{},
	}[name]
	if !ok {
		return nil, errors.Errorf("unknown command: %q", name)
	}
	return v, nil
}

// errFlagParseError is a sentinel error value used to determine whether error
// originates from flagset that already reported error to stderr so its
// reporting can be omitted
var errFlagParseError = errors.New("flag parse error")

// parseArgs defines new flag set with flags from argStruct that writes its
// errors to w, then calls flag set Parse method on provided raw arguments and
// calls Validate() method on provided argStruct. If parseArgs returns
// errFlagParseError, it means that flag set already reported error to w.
func parseArgs(command string, argStruct validator, w io.Writer, raw []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, argStruct)
	if err := fs.Parse(raw); err != nil {
		return errFlagParseError
	}
	return argStruct.Validate()
}

type runArgs struct {
	Addr string `flag:"addr,$DEPLOYCTL_ADDR, registry host address (host:port)"`
	Fp   string `flag:"fp,$DEPLOYCTL_FINGERPRINT, sha256 host key fingerprint (sha256:...)"`
}

func (a *runArgs) Validate() error {
	if a.Addr == "" || a.Fp == "" {
		return errors.New("both addr and fp should be set")
	}
	return nil
}

func usageFunc(printDefaults func()) func() {
	return func() {
		fmt.Fprintln(os.Stderr, "Usage: deployctl [flags] subcommand [subcommand flags]")
		printDefaults()
		fmt.Fprintln(os.Stderr, "\nSubcommands:\n")
		fmt.Fprintln(os.Stderr, strings.TrimSpace(shared.CommandsListing))
	}
}

var knownCommands = []string{"addver", "addconf",
	"changeconf", "showconf",
	"components", "configurations",
	"showcomp",
	"delver",
	"delcomp",
	"delconf",
}
