// Command deployctl implements single-command operator's interface to manage
// deployments running under deploy-registry and deploy-agent
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	if err := dispatch(args.Addr, args.Key, args.Fp, fs.Args()); err != nil {
		if err == errFlagParseError {
			os.Exit(2)
		}
		if _, ok := err.(*ssh.ExitError); !ok { // don't write "Process exited with status 1"
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func dispatch(addr, keyFile, fingerprint string, rawArgs []string) error {
	if len(rawArgs) == 0 {
		return errors.New("nothing to do")
	}
	cmd, args := rawArgs[0], rawArgs[1:]
	switch cmd {
	case "components", "configurations":
		return proxyCommand(addr, keyFile, fingerprint, rawArgs)
	case "addver":
		val := &shared.ArgsAddVersionByFile{}
		if err := parseArgs(cmd, val, os.Stderr, args); err != nil {
			return err
		}
		return uploadAndUpdate(addr, keyFile, fingerprint, val)
	}
	val, err := validatorForCommand(cmd)
	if err != nil {
		return err
	}
	if err := parseArgs(cmd, val, os.Stderr, args); err != nil {
		return err
	}
	return proxyCommand(addr, keyFile, fingerprint, rawArgs)
}

func uploadAndUpdate(addr, keyFile, fingerprint string, args *shared.ArgsAddVersionByFile) error {
	src, err := os.Open(args.File)
	if err != nil {
		return err
	}
	defer src.Close()
	client, cancel, err := dialSSH(addr, keyFile, fingerprint)
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
	pr, pw := io.Pipe()
	defer pw.Close()
	defer pr.Close()
	verifyErr := make(chan error)
	go func() {
		err := decodeArchive(pr)
		pr.CloseWithError(err)
		verifyErr <- err
	}()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(pw, dst, h), src); err != nil {
		return errors.WithMessage(err, "upload failure")
	}
	if err := dst.Close(); err != nil {
		return err
	}
	// decodeArchive buffers data, so it may not fail during io.Copy to
	// MultiWriter above if data is copied faster than decoded; ensure we
	// check decode result
	switch err := <-verifyErr; err {
	case io.EOF:
	default:
		return errors.WithMessage(err, "file validation failed")
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

func dialSSH(addr, keyFile, fingerprint string) (client *ssh.Client, closeFunc func(), err error) {
	var signers []ssh.Signer
	switch {
	case keyFile != "":
		s, err := readKey(keyFile)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to read/parse key file %q", keyFile)
		}
		signers = append(signers, s)
	default:
		agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, nil, errors.WithMessage(err, "cannot connect to ssh-agent, check if SSH_AUTH_SOCK is set")
		}
		defer agentConn.Close()
		sshAgent := agent.NewClient(agentConn)
		signers, err = sshAgent.Signers()
		if err != nil {
			return nil, nil, err
		}
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
	closeFunc = func() { client.Close() }
	return client, closeFunc, nil
}

func proxyCommand(addr, keyFile, fingerprint string, args []string) error {
	client, cancel, err := dialSSH(addr, keyFile, fingerprint)
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
	switch name {
	case "delver":
		return &shared.ArgsDelVersion{}, nil
	case "delcomp":
		return &shared.ArgsDelComponent{}, nil
	case "addconf":
		return &shared.ArgsAddConfiguration{}, nil
	case "delconf":
		return &shared.ArgsDelConfiguration{}, nil
	case "changeconf":
		return &shared.ArgsUpdateConfiguration{}, nil
	case "bumpconf":
		return &shared.ArgsBumpConfiguration{}, nil
	case "showconf":
		return &shared.ArgsShowConfiguration{}, nil
	case "showcomp":
		return &shared.ArgsShowComponent{}, nil
	}
	return nil, errors.Errorf("unknown command: %q", name)
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
	Key  string `flag:"key,ssh private key to use; if not set, ssh-agent is used"`
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
		fmt.Fprintln(os.Stderr, "\nSubcommands:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, strings.TrimSpace(shared.CommandsListing))
	}
}

// decodeArchive reads and unpacks rd as tar.gz stream, discarding data and
// returning first error it encounters
func decodeArchive(rd io.Reader) error {
	gr, err := gzip.NewReader(rd)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		if _, err := tr.Next(); err != nil {
			return err
		}
		if _, err := io.Copy(ioutil.Discard, tr); err != nil {
			return err
		}
	}
}

func readKey(name string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}
