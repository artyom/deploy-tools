// Command deploy-agent tracks single configuration against registry, updates
// local state as required and runs deploy script.
package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
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
		Poll:   30 * time.Second,
	}
	autoflags.Parse(args)
	log := log.New(os.Stderr, "", log.LstdFlags)
	if err := run(args, log); err != nil {
		log.Fatal(err)
	}
}

type mainArgs struct {
	State    string        `flag:"state,file to save state to"`
	Name     string        `flag:"name,configuration to track"`
	Key      string        `flag:"key,ssh private key to use"`
	Addr     string        `flag:"addr,registry address (host:port)"`
	Fp       string        `flag:"fp,registry server key fingerprint"`
	Dir      string        `flag:"dir,directory to store downloaded and unpacked files"`
	Script   string        `flag:"script,script to run on deploys"`
	CleanOld bool          `flag:"cleanold,remove unreferenced unpacked files after successful switch"`
	Verbose  bool          `flag:"v,be more chatty about what's happening"`
	Poll     time.Duration `flag:"poll,registry poll interval"`
}

func run(args *mainArgs, log logger.Interface) error {
	if args.Name == "" {
		return errors.New("empty configuration name")
	}
	if args.State == "" {
		return errors.New("no state file set")
	}
	unlockDir, err := lockDir(args.Dir)
	if err != nil {
		return err
	}
	defer unlockDir()
	cfg, err := newClientConfig(args.Key, args.Fp)
	if err != nil {
		return err
	}
	waitfunc := pollRandomizer(args.Poll, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go callOnSignal(func(s os.Signal) { log.Println(s); cancel() }, syscall.SIGINT, syscall.SIGTERM)
	for {
		if err := cycle(ctx, args, cfg, log); err != nil {
			log.Println(err)
		}
		select {
		case <-waitfunc():
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
	if validateHash(newState.Hash) != nil {
		return errors.Errorf("invalid state hash value: %q, expecting sha256 sum", newState.Hash)
	}
	if len(newState.Layers) == 0 {
		return errors.New("invalid state: no layers")
	}
	if newState.Hash == state.Hash {
		return nil
	}
	if args.Verbose {
		var b strings.Builder
		fmt.Fprintln(&b, "configuration update available:", newState.Hash)
		for i, l := range newState.Layers {
			fmt.Fprintf(&b, "\tcomponent %d: %q, version: %q\n", i+1, l.Name, l.Version)
		}
		log.Println(b.String())
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
		log.Println("switched to the new configuration:", newState.Hash)
	}
	if args.CleanOld {
		if err := cleanUnpacked(filepath.Join(args.Dir, unpackedDir), newState.Hash); err != nil {
			log.Println("error cleaning old unpacked files:", err)
		}
	}
	return nil
}

func cleanUnpacked(dir, hashKeep string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	fis, err := f.Readdir(0)
	if err != nil {
		return err
	}
	for _, fi := range fis {
		switch name := fi.Name(); {
		default:
			continue
		case name == hashKeep || name == hashKeep+".ok":
			continue
		case len(name) == 64 && fi.IsDir():
		case len(name) == 64+3 && strings.HasSuffix(name, ".ok"):
		}
		// remove .ok flag BEFORE removing directory, so even if
		// directory removal fails mid-way, there's no .ok flag left
		if len(fi.Name()) == 64 && fi.IsDir() {
			if err := os.RemoveAll(filepath.Join(dir, fi.Name()+".ok")); err != nil {
				return err
			}
		}
		if err := os.RemoveAll(filepath.Join(dir, fi.Name())); err != nil {
			return err
		}
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
		if time.Since(info.ModTime()) < age {
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
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := ioutil.TempFile(dir, "temp-state-")
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
	if err := os.MkdirAll(dst, 0755); err != nil {
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
	if err := os.MkdirAll(dir, 0755); err != nil {
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

// pollRandomizer returns function calling time.After(...) on base duration
// randomized by adding up to n seconds to it. Returned function is unsafe for
// concurrent use.
func pollRandomizer(base time.Duration, n int) func() <-chan time.Time {
	if base < 0 {
		base = 15 * time.Second
	}
	if n <= 0 {
		n = 1
	}
	r := rand.New(rand.NewSource(int64(os.Getpid())))
	return func() <-chan time.Time {
		return time.After(base + time.Duration(r.Intn(n))*time.Second)
	}
}

// lockDir creates directory dir if necessary and tries to acquire exclusive
// lock on it. Returned unlockFn unlocks directory.
func lockDir(dir string) (unlockFn func(), err error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.Wrapf(err, "cannot acquire exclusive lock on %q", dir)
	}
	return func() { f.Close() }, nil
}

// validateHash checks whether s is a valid hex representation of sha256 hash
func validateHash(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if l := len(b); l != sha256.Size {
		return errors.Errorf("length mismatch: %d", l)
	}
	return nil
}
