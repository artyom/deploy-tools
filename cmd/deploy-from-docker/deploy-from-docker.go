// Command deploy-from-docker creates/updates single configuration from the
// docker image save output read as stdin.
//
// Usage example:
//
// 	docker save alpine:latest | deploy-from-docker
//
// This would create/update configuration named alpine.latest
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/artyom/autoflags"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

// defaults can be pre-defined on build time using -ldflags="-X=..."
var defaultAddress, defaultFingerprint string

func main() {
	args := &runArgs{
		Addr: defaultAddress,
		Fp:   defaultFingerprint,
	}
	if val, ok := os.LookupEnv("DEPLOYCTL_ADDR"); ok {
		args.Addr = val
	}
	if val, ok := os.LookupEnv("DEPLOYCTL_FINGERPRINT"); ok {
		args.Fp = val
	}
	autoflags.Parse(args)
	if err := args.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n\n", err)
		flag.Usage()
		os.Exit(2)
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args *runArgs) error {
	if err := args.Validate(); err != nil {
		return err
	}
	var hostKeyCallback ssh.HostKeyCallback
	var err error
	switch args.Fp {
	case "":
		hostKeyCallback, err = knownhosts.New(os.ExpandEnv("${HOME}/.ssh/known_hosts"))
		if err != nil {
			return err
		}
	default:
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if hostFp := ssh.FingerprintSHA256(key); hostFp != args.Fp {
				return errors.Errorf("host key fingerprint mismatch: %v", hostFp)
			}
			return nil
		}
	}
	name, layers, err := repack(os.Stdin)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range layers {
			c.Close()
		}
	}()
	if args.Name != "" {
		name = args.Name
	}
	client, cclose, err := dialSSH(args.Addr, args.Key, hostKeyCallback)
	if err != nil {
		return err
	}
	defer cclose()
	return uploadAndSwitch(client, name, layers)
}

func uploadAndSwitch(client *ssh.Client, name string, layers []io.ReadCloser) error {
	if name == "" {
		return errors.New("empty name")
	}
	if len(layers) == 0 {
		return errors.New("no layers found")
	}
	name = strings.Map(func(r rune) rune {
		switch r {
		case ':', '/':
			return '.'
		}
		return r
	}, name)
	components := make([]string, 0, len(layers))
	for i, rd := range layers {
		lname := fmt.Sprintf("%s.l%d", name, i+1)
		fmt.Fprintf(os.Stderr, "uploading %d/%d: %q\n", i+1, len(layers), lname)
		h, err := upload(client, rd)
		if err != nil {
			return errors.WithMessage(err, "upload failed")
		}
		hash := fmt.Sprintf("%x", h)
		if err := addVersion(client, lname, hash); err != nil {
			return errors.WithMessage(err, "failed to add version")
		}
		components = append(components, lname+":"+hash)
	}
	cmdArgs := make([]string, 0, 2+len(components))
	cmdArgs = append(cmdArgs, "addconf", fmt.Sprintf("-name=%q", name))
	for _, s := range components {
		cmdArgs = append(cmdArgs, fmt.Sprintf("-layer=%q", s))
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	fmt.Fprintf(os.Stderr, "updating configuration %q\n", name)
	return session.Run(strings.Join(cmdArgs, " "))
}

func addVersion(client *ssh.Client, name, hash string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	buf, err := session.CombinedOutput(
		fmt.Sprintf("addver -name=%q -version=%s -hash=%[2]s", name, hash))
	if err != nil && bytes.Contains(buf, []byte("already exists")) {
		return nil
	}
	if err != nil {
		os.Stderr.Write(buf)
		return err
	}
	return nil
}

func upload(client *ssh.Client, src io.Reader) ([]byte, error) {
	sftpconn, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	defer sftpconn.Close()
	dst, err := sftpconn.Create("upload")
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	h := sha256.New()
	gw := gzip.NewWriter(io.MultiWriter(dst, h))
	if _, err := io.Copy(gw, src); err != nil {
		return nil, errors.WithMessage(err, "upload failure")
	}
	if err := gw.Close(); err != nil {
		return nil, errors.WithMessage(err, "upload failure")
	}
	return h.Sum(nil), dst.Close()
}

func dialSSH(addr, keyFile string, hostKeyCallback ssh.HostKeyCallback) (client *ssh.Client, closeFunc func(), err error) {
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
		User:            os.Getenv("USER"),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		Timeout:         30 * time.Second,
		HostKeyCallback: hostKeyCallback,
	}
	client, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	closeFunc = func() { client.Close() }
	return client, closeFunc, nil
}

type runArgs struct {
	Addr string `flag:"addr,$DEPLOYCTL_ADDR, registry host address (host:port)"`
	Fp   string `flag:"fp,$DEPLOYCTL_FINGERPRINT, sha256 host key fingerprint (sha256:...)"`
	Key  string `flag:"key,ssh private key to use; if not set, ssh-agent is used"`
	Name string `flag:"name,configuration name; derived from docker image tag if not set"`
}

func (a *runArgs) Validate() error {
	if a.Addr == "" {
		return errors.New("addr should be set")
	}
	return nil
}

func init() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "docker save myimage:tag | deploy-from-docker [flags]")
		flag.PrintDefaults()
	}
}

func readKey(name string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func repack(input io.Reader) (string, []io.ReadCloser, error) {
	tr := tar.NewReader(input)
	layers := make(map[string]*os.File)
	var name string
	var mlayers []*layerMeta
	var happyPath bool
	defer func() {
		if !happyPath {
			for _, f := range layers {
				f.Close()
			}
		}
	}()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if err := fillSkips(layers, mlayers); err != nil {
				return "", nil, err
			}
			ret := make([]io.ReadCloser, 0, len(mlayers))
			defer func() { // make sure to unblock io.PipeWriters
				if !happyPath {
					for _, c := range ret {
						c.Close()
					}
				}
			}()
			for _, meta := range mlayers {
				f, ok := layers[meta.name]
				if !ok {
					return "", nil, fmt.Errorf("manifest references unknown layer %q", meta.name)
				}
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					return "", nil, err
				}
				ret = append(ret, restream(f, meta.skip))
			}
			happyPath = true
			return name, ret, nil
		}
		if err != nil {
			return "", nil, err
		}
		if strings.HasSuffix(hdr.Name, "/layer.tar") {
			f, err := dumpStream(tr)
			if err != nil {
				return "", nil, err
			}
			layers[hdr.Name] = f
			continue
		}
		if hdr.Name == "manifest.json" {
			if name, mlayers, err = decodeManifest(tr); err != nil {
				return "", nil, err
			}
		}
	}
}

func restream(input io.ReadCloser, skip map[string]struct{}) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(copyStream(pw, input, skip)) }()
	return pr
}

func copyStream(output io.Writer, input io.ReadCloser, skip map[string]struct{}) error {
	defer input.Close()
	tr := tar.NewReader(input)
	tw := tar.NewWriter(output)
	defer tw.Close()
tarLoop:
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return tw.Close()
		}
		if err != nil {
			return err
		}
		if _, ok := skip[hdr.Name]; ok {
			continue
		}
		if hdr.Mode == 0 && strings.HasPrefix(path.Base(hdr.Name), tombstone) {
			continue
		}
		for prefix := range skip {
			if strings.HasPrefix(hdr.Name, prefix+"/") {
				continue tarLoop
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
}

func decodeManifest(r io.Reader) (string, []*layerMeta, error) {
	data := []struct {
		RepoTags []string
		Layers   []string
	}{}
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return "", nil, err
	}
	if l := len(data); l != 1 {
		return "", nil, fmt.Errorf("manifest.json describes %d objects, call docker save for a single image", l)
	}
	out := make([]*layerMeta, len(data[0].Layers))
	for i, name := range data[0].Layers {
		out[i] = &layerMeta{name: name}
	}
	var name string
	if len(data[0].RepoTags) > 0 {
		name = data[0].RepoTags[0]
	}
	return name, out, nil
}

func dumpStream(r io.Reader) (*os.File, error) {
	f, err := ioutil.TempFile("", "merge-docker-save-")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type layerMeta struct {
	name string
	skip map[string]struct{}
}

// fillSkips fills skip fields of mlayers elements from the tombstone items
// discovered in files referenced in layers map. skip fields filled in such
// a way that for each layer it holds a set of names that should be skipped when
// repacking tar stream since these items would be removed by the following
// layers.
func fillSkips(layers map[string]*os.File, mlayers []*layerMeta) error {
	for i := len(mlayers) - 1; i > 0; i-- {
		meta := mlayers[i]
		f, ok := layers[meta.name]
		if !ok {
			return fmt.Errorf("manifest references unknown layer %q", meta.name)
		}
		skips, err := findSkips(f)
		if err != nil {
			return err
		}
		if skips == nil {
			continue
		}
		for _, meta := range mlayers[:i] {
			if meta.skip == nil {
				meta.skip = make(map[string]struct{})
			}
			for _, s := range skips {
				meta.skip[s] = struct{}{}
			}
		}
	}
	return nil
}

// findSkips scans tar archive for tombstone items and returns list of
// corresponding file names.
func findSkips(f io.ReadSeeker) ([]string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var skips []string
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return skips, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Mode != 0 {
			continue
		}
		if base := path.Base(hdr.Name); strings.HasPrefix(base, tombstone) && base != tombstone {
			skips = append(skips, path.Join(path.Dir(hdr.Name), strings.TrimPrefix(base, tombstone)))
		}
	}
}

const tombstone = ".wh." // prefix docker uses to mark deleted files
