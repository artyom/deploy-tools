// Command deploy-agent tracks single configuration against registry, updates
// local state as required and runs deploy script.
package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/artyom/autoflags"
	"github.com/artyom/logger"
	"github.com/artyom/untar"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

func main() {
	args := &mainArgs{
		State:  "state.json",
		Key:    "id_ecdsa",
		Addr:   "localhost:2022",
		Dir:    ".",
		Script: "./deploy.sh",
	}
	autoflags.Define(args)
	flag.Parse()
	log := log.New(os.Stderr, "", log.LstdFlags)
	if err := run(args, log); err != nil {
		log.Fatal(err)
	}
}

type mainArgs struct {
	State    string `flag:"state,file to save state to"`
	Name     string `flag:"name,configuration to track"`
	Key      string `flag:"key,ssh private key to use"`
	Addr     string `flag:"addr,registry address (host:port)"`
	Fp       string `flag:"fp,registry server key fingerprint"`
	Dir      string `flag:"dir,directory to store downloaded and unpacked files"`
	Script   string `flag:"script,script to run on deploys"`
	CleanOld bool   `flag:"cleanold,try to remove previous state unpacked files after switching state"`
	Verbose  bool   `flag:"v,be more chatty about what's happening"`
}

func run(args *mainArgs, log logger.Interface) error {
	if args.Name == "" {
		return errors.New("empty configuration name")
	}
	if args.State == "" {
		return errors.New("no state file set")
	}
	cfg, err := newClientConfig(args.Key, args.Fp)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go callOnSignal(func(s os.Signal) { log.Println(s); cancel() }, syscall.SIGINT, syscall.SIGTERM)
	for {
		if err := cycle(ctx, args, cfg, log); err != nil {
			log.Println(err)
		}
		select {
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
			return nil
		}
	}
}

func cycle(ctx context.Context, args *mainArgs, cfg *ssh.ClientConfig, log logger.Interface) error {
	state, err := readLocalConfiguration(args.State)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		state = &configuration{}
	default:
		return err
	}
	if err := cleanCache(filepath.Join(args.Dir, cacheDir), state.Layers, time.Hour); err != nil {
		log.Println("error cleaning cache directory:", err)
	}
	client, err := ssh.Dial("tcp", args.Addr, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	sconn, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sconn.Close()
	newState, err := readRemoteConfiguration(path.Join("configs", args.Name+".json"), sconn)
	if err != nil {
		return err
	}
	if len(newState.Hash) != 64 {
		return errors.Errorf("invalid state hash value: %q, expecting sha256 sum", newState.Hash)
	}
	if newState.Hash == state.Hash {
		return nil
	}
	if args.Verbose {
		log.Println("configuration update available:", newState.Hash)
		for i, l := range newState.Layers {
			log.Printf("\tcomponent %d: %q, version: %q", i+1, l.Name, l.Version)
		}
	}
	if err := downloadMissing(ctx, sconn, filepath.Join(args.Dir, cacheDir), newState.Layers); err != nil {
		return err
	}
	sconn.Close()
	if err := unpackLayers(ctx, filepath.Join(args.Dir, unpackedDir, filepath.Base(newState.Hash)),
		filepath.Join(args.Dir, cacheDir), newState.Layers); err != nil {
		return err
	}
	if args.Script != "" {
		if err := runDeploy(ctx, args.Script, filepath.Join(args.Dir, unpackedDir), state, newState); err != nil {
			return err
		}
	}
	if err := saveState(args.State, 0644, newState); err != nil {
		return err
	}
	if args.Verbose {
		log.Println("switched to new configuration:", newState.Hash)
	}
	if args.CleanOld && state.Hash != "" {
		oldDir := filepath.Join(args.Dir, unpackedDir, filepath.Base(state.Hash))
		if err := os.RemoveAll(oldDir); err != nil {
			log.Println("failed to remove old state directory:", err)
		}
		_ = os.Remove(oldDir + ".ok")
	}
	return nil
}

func cleanCache(dir string, layers []layer, age time.Duration) error {
	keep := make(map[string]struct{}, len(layers))
	for _, l := range layers {
		keep[l.Hash] = struct{}{}
	}
	fn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}
		if _, ok := keep[filepath.Base(path)]; ok || !info.Mode().IsRegular() {
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), tempDlPrefix) {
			return errors.WithStack(os.Remove(path))
		}
		if time.Now().Sub(info.ModTime()) < age {
			return nil
		}
		return errors.WithStack(os.Remove(path))
	}
	return filepath.Walk(dir, fn)
}

func runDeploy(ctx context.Context, script, dir string, oldState, newState *configuration) error {
	stateFile, err := saveStateTemp("", 0644, newState)
	if err != nil {
		return err
	}
	defer os.Remove(stateFile)
	cmd := exec.CommandContext(ctx, script)
	cmd.Env = []string{
		"OLDID=" + oldState.Hash,
		"OLDROOT=" + filepath.Join(dir, oldState.Hash),
		"NEWID=" + newState.Hash,
		"NEWROOT=" + filepath.Join(dir, newState.Hash),
		"STATEFILE=" + stateFile,
	}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "SHELL"} {
		if val, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+val)
		}
	}
	for i, l := range newState.Layers {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("LAYER_%d_NAME=%s", i, l.Name),
			fmt.Sprintf("LAYER_%d_VERSION=%s", i, l.Version),
		)
	}
	return errors.Wrapf(cmd.Run(), "%q call failure", script)
}

func saveStateTemp(dir string, mode os.FileMode, state *configuration) (string, error) {
	f, err := ioutil.TempFile(dir, "json-state-")
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	if err := enc.Encode(state); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

func saveState(dst string, mode os.FileMode, state *configuration) error {
	f, err := ioutil.TempFile(filepath.Dir(dst), "temp-state-")
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	if err := enc.Encode(state); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), dst)
}

func unpackLayers(ctx context.Context, dst, filesDir string, layers []layer) error {
	touchfile := dst + ".ok"
	if _, err := os.Stat(touchfile); err == nil {
		if _, err := os.Stat(dst); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(dst, 0750); err != nil {
		return err
	}
	for _, l := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(l.Hash) != 64 {
			return errors.Errorf("invalid length of layer hash: %v", l)
		}
		srcName := filepath.Join(filesDir, filepath.Base(l.Hash))
		if err := untarTo(srcName, dst); err != nil {
			return err
		}
	}
	_ = touch(touchfile)
	return nil
}

func untarTo(name, dir string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	defer syscall.Umask(syscall.Umask(0))
	return untar.Untar(gr, dir)
}

func downloadMissing(ctx context.Context, sconn *sftp.Client, dir string, layers []layer) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	for _, l := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(l.Hash) != 64 {
			return errors.Errorf("invalid length of layer hash: %v", l)
		}
		dstName := filepath.Join(dir, filepath.Base(l.Hash))
		if _, err := os.Stat(dstName); err == nil {
			continue
		}
		if err := downloadFile(sconn, dstName, l.File, l.Hash); err != nil {
			return err
		}
	}
	return nil
}

func downloadFile(sconn *sftp.Client, dst, src, contentHash string) error {
	dstFile, err := ioutil.TempFile(filepath.Dir(dst), tempDlPrefix)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	defer os.Remove(dstFile.Name())
	srcFile, err := sconn.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	h := sha256.New()
	tr := io.TeeReader(srcFile, h)
	if _, err := io.Copy(dstFile, tr); err != nil {
		return err
	}
	if contentHash != fmt.Sprintf("%x", h.Sum(nil)) {
		return errors.Errorf("downloaded file hash mismatch: %v", src)
	}
	if err := dstFile.Close(); err != nil {
		return err
	}
	return os.Rename(dstFile.Name(), dst)
}

func readRemoteConfiguration(name string, sconn *sftp.Client) (*configuration, error) {
	f, err := sconn.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeConfiguration(f)
}

func readLocalConfiguration(name string) (*configuration, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeConfiguration(f)
}

func decodeConfiguration(r io.Reader) (*configuration, error) {
	var cfg configuration
	if err := json.NewDecoder(r).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func newClientConfig(keyfile, fingerprint string) (*ssh.ClientConfig, error) {
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return nil, errors.New("invalid server key fingerprint, expecting SHA256 fingerprint")
	}
	key, err := readKey(keyfile)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: "deploy-agent",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if hostFp := ssh.FingerprintSHA256(key); hostFp != fingerprint {
				return errors.Errorf("host key fingerprint mismatch: %v", hostFp)
			}
			return nil
		},
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
		Timeout: 30 * time.Second,
	}
	return config, nil
}

func readKey(name string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func touch(name string) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return err
	}
	return f.Close()
}

func callOnSignal(fn func(os.Signal), sig ...os.Signal) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, sig...)
	defer signal.Stop(sigCh)
	fn(<-sigCh)
}

type configuration struct {
	Name   string
	Mtime  time.Time
	Hash   string
	Layers []layer
}

type layer struct {
	Name    string
	Version string
	File    string
	Hash    string
	Ctime   time.Time
}

const (
	cacheDir     = "cache"
	unpackedDir  = "unpacked"
	tempDlPrefix = "temp-"
)
