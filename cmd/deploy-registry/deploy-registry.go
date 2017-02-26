// Command deploy-registry implements server for deployment management
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/artyom/autoflags"
	"github.com/artyom/deploy-tools/cmd/deploy-registry/internal/internals"
	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

func main() {
	args := struct {
		Addr    string `flag:"addr,address to listen"`
		Dir     string `flag:"dir,data directory"`
		OpAuth  string `flag:"opauth,authorized_keys for operators"`
		SrvAuth string `flag:"srvauth,authorized_keys for services"`
	}{
		Addr:    "localhost:2022",
		Dir:     ".",
		OpAuth:  "operator.keys",
		SrvAuth: "service.keys",
	}
	autoflags.Define(&args)
	flag.Parse()
	if err := run(runConf(args)); err != nil {
		log.Fatal(err)
	}
}

type runConf struct {
	Addr    string
	Dir     string
	OpAuth  string
	SrvAuth string
}

const (
	filesDir   = "files"
	uploadDir  = "uploads"
	hashPrefix = "sha256:"

	bktByVersion  = "byVersion"
	bktByTime     = "byTime"
	bktComponents = "components"
	bktConfigs    = "configs"
)

func run(args runConf) error {
	hostKey, config, err := internals.ServerSetup(filepath.Join(args.Dir, "id_ecdsa"), args.OpAuth, args.SrvAuth)
	if err != nil {
		return err
	}
	log.Println("host key fingerprint:", ssh.FingerprintSHA256(hostKey.PublicKey()))
	tr, err := newTracker(filepath.Join(args.Dir, "state.db"), args.Dir)
	if err != nil {
		return err
	}
	defer tr.Close()

	ln, err := net.Listen("tcp", args.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Minute)) // TODO
			if err := serveConn(conn, config, tr); err != nil {
				log.Printf("%+v", err)
			}
		}(conn)
	}
}

func serveConn(conn net.Conn, config *ssh.ServerConfig, tr *tracker) error {
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return errors.WithStack(err)
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	isServiceUser := internals.IsServiceUser(sconn.Permissions)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return errors.WithStack(err)
		}
		switch {
		case isServiceUser:
			go handleServiceSession(channel, requests, tr)
		default:
			go handleOperatorSession(channel, requests, tr)
		}
	}
	return nil
}

func handleServiceSession(sshCh ssh.Channel, requests <-chan *ssh.Request, tr *tracker) {
	for req := range requests {
		if !isSftpRequest(req) {
			req.Reply(false, nil)
			continue
		}
		go func() {
			defer sshCh.Close() // SSH_MSG_CHANNEL_CLOSE
			s := internals.NewDownloadServer(sshCh, tr.fileInfoFunc, tr.fileReadFunc)
			_ = s.Serve()
		}()
		req.Reply(true, nil)
	}
}

func handleOperatorSession(sshCh ssh.Channel, requests <-chan *ssh.Request, tr *tracker) {
	for req := range requests {
		var ok bool
		switch {
		case req.Type == "pty-req":
			req.Reply(true, nil)
			continue
		case req.Type == "shell":
			ok = true
			go func() {
				defer sshCh.Close()      // SSH_MSG_CHANNEL_CLOSE
				defer sshCh.CloseWrite() // SSH_MSG_CHANNEL_EOF
				defer sshCh.SendRequest("eow@openssh.com", false, nil)
				switch err := serveTerminal(tr, sshCh); err {
				case nil:
					sshCh.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{0}))
				default:
					sshCh.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{1}))
				}
			}()
		case isSftpRequest(req):
			ok = true
			go func() {
				defer sshCh.Close() // SSH_MSG_CHANNEL_CLOSE
				s := internals.NewUploadServer(sshCh,
					filepath.Join(tr.dir, uploadDir),
					tr.uploadCallback)
				_ = s.Serve()
			}()
		}
		req.Reply(ok, nil)
		if ok {
			break
		}
	}
	for req := range requests {
		req.Reply(false, nil)
	}
}

type tracker struct {
	db  *bolt.DB
	dir string // root directory which holds "files" and "uploads" subdirectories

	mu sync.Mutex
	// uploads holds mapping of uploaded file hash to its full (temporary)
	// name
	uploads map[string]string
	st      *syscall.Stat_t // used to attach to virtual files
}

func (tr *tracker) uploadCallback(name, hash string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.uploads[hash] = name
}

func (tr *tracker) fileInfoFunc(r sftp.Request) ([]os.FileInfo, error) {
	switch r.Method {
	case "List":
		return tr.listDirs(r.Filepath)
	case "Stat":
		var out []os.FileInfo
		st, err := tr.statPath(r.Filepath)
		if st != nil {
			out = []os.FileInfo{st}
		}
		return out, err
	}
	return nil, syscall.EPERM // TODO
}

func (tr *tracker) statPath(reqPath string) (os.FileInfo, error) {
	reqPath = path.Clean(reqPath)
	var hasMatch bool
	for _, pat := range []string{"/", "/files", "/configs", "/files/?*", "/configs/?*.json"} {
		if ok, _ := path.Match(pat, reqPath); ok {
			hasMatch = true
			break
		}
	}
	if !hasMatch {
		return nil, syscall.ENOENT
	}
	if reqPath == "/files" {
		return os.Stat(filepath.Join(tr.dir, filesDir))
	}
	if path.Dir(reqPath) == "/files" {
		return os.Stat(filepath.Join(tr.dir, filesDir, path.Base(reqPath)))
	}
	now := time.Now().UTC()
	switch reqPath {
	case "/":
		return internals.NewFile("/", true, now, nil, tr.st), nil
	case "/configs":
		return internals.NewFile("configs", true, now, nil, tr.st), nil
	}
	if ok, err := path.Match("/configs/?*.json", reqPath); err != nil || !ok {
		return nil, syscall.ENOENT
	}
	// the only case left unprocessed so far is "/configs/?*.json"
	name := strings.TrimSuffix(path.Base(reqPath), ".json")
	data, err := fetchKey(tr.db, "configs", name, "current")
	if err != nil {
		return nil, err
	}
	return internals.NewFile(path.Base(reqPath), false, now, data, tr.st), nil
}

func (tr *tracker) listDirs(reqPath string) ([]os.FileInfo, error) {
	switch reqPath {
	default:
		return nil, syscall.EPERM
	case "/files":
		f, err := os.Open(filepath.Join(tr.dir, filesDir))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return f.Readdir(0)
	case "/configs":
		configs, err := fetchConfigs(tr.db)
		if err != nil {
			return nil, err
		}
		return configsVirtualFiles(configs, tr.st), nil
	case "/":
	}
	statFiles, err := os.Stat(filepath.Join(tr.dir, filesDir))
	if err != nil {
		return nil, err
	}
	statConfigs := internals.NewFile("configs", true, statFiles.ModTime(), nil, tr.st)
	return []os.FileInfo{statConfigs, statFiles}, nil
}

func (tr *tracker) fileReadFunc(r sftp.Request) (io.ReaderAt, error) {
	// r.Filepath may match one of the following patterns:
	// 1. "/configs/?*.json" — virtual file w/json dump of config
	// 2. "/files/?*" — real file from disk
	return nil, syscall.EPERM // TODO
}

func newTracker(name, dir string) (*tracker, error) {
	db, err := bolt.Open(name, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	return &tracker{
		db:      db,
		dir:     dir,
		uploads: make(map[string]string),
		st:      &syscall.Stat_t{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())},
	}, nil
}

func (tr *tracker) Close() error { return tr.db.Close() }

// saveKey saves provided value in a boltDB at given address. Address should
// have at least 2 elements, as boltDB does not allow root bucket values. Last
// element of address specifies leaf key. Buckets are created as necessary.
func saveKey(db *bolt.DB, value []byte, addr ...string) error {
	if db == nil || len(value) == 0 || len(addr) < 2 {
		return errors.New("invalid saveKey arguments")
	}
	return db.Update(func(tx *bolt.Tx) error {
		return saveTxKey(tx, value, addr...)
	})
}

func multiUpdate(db *bolt.DB, funcs ...func(*bolt.Tx) error) error {
	if len(funcs) == 0 {
		return nil
	}
	return db.Update(func(tx *bolt.Tx) error {
		for _, fn := range funcs {
			if err := fn(tx); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
}

func saveTxKey(tx *bolt.Tx, value []byte, addr ...string) error {
	val := make([]byte, len(value))
	copy(val, value)
	bkt, err := tx.CreateBucketIfNotExists([]byte(addr[0]))
	if err != nil {
		return errors.WithStack(err)
	}
	for _, k := range addr[1 : len(addr)-1] {
		if bkt, err = tx.CreateBucketIfNotExists([]byte(k)); err != nil {
			return errors.WithStack(err)
		}
	}
	return errors.WithStack(bkt.Put([]byte(addr[len(addr)-1]), val))
}

// fetchKey retrieves value from provided database. Value address specified with
// addr string slice, which may address nested buckets. addr should have at
// least 2 elements, as boltDB does not allow root bucket values. Error returned
// only on read operations, if key is not found, nil byte slice is returned.
func fetchKey(db *bolt.DB, addr ...string) ([]byte, error) {
	if db == nil || len(addr) < 2 {
		return nil, errors.New("invalid fetchKey arguments")
	}
	var out []byte
	err := db.View(func(tx *bolt.Tx) error {
		out = fetchTxKey(tx, addr...)
		return nil
	})
	return out, errors.WithStack(err)
}

func fetchTxBucketKeys(tx *bolt.Tx, addr ...string) []string {
	bkt := tx.Bucket([]byte(addr[0]))
	if bkt == nil {
		return nil
	}
	for _, k := range addr[1:] {
		if bkt = bkt.Bucket([]byte(k)); bkt == nil {
			return nil
		}
	}
	var out []string
	cur := bkt.Cursor()
	for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
		out = append(out, string(k))
	}
	return out
}

func fetchTxKey(tx *bolt.Tx, addr ...string) []byte {
	bkt := tx.Bucket([]byte(addr[0]))
	if bkt == nil {
		return nil
	}
	for _, k := range addr[1:] {
		if v := bkt.Get([]byte(k)); v != nil {
			out := make([]byte, len(v))
			copy(out, v)
			return out
		}
		if bkt = bkt.Bucket([]byte(k)); bkt == nil {
			return nil
		}
	}
	return nil
}

func fetchConfigs(db *bolt.DB, names ...string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(names))
	err := db.View(func(tx *bolt.Tx) error {
		if len(names) == 0 {
			names = fetchTxBucketKeys(tx, "configs")
		}
		for _, k := range names {
			if val := fetchTxKey(tx, "configs", k, "current"); val != nil {
				out[k] = val
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return out, nil
}

func configsVirtualFiles(m map[string][]byte, st *syscall.Stat_t) []os.FileInfo {
	var out []os.FileInfo
	now := time.Now().UTC()
	for k, v := range m {
		out = append(out, internals.NewFile(k+".json", false, now, v, st))
	}
	return out
}

// ComponentVersion represents single version of component
type ComponentVersion struct {
	Name    string
	Version string
	File    string
	Hash    string
	Ctime   time.Time
}

const tsFormat = `2006-01-02T15:04:05`

func (cv *ComponentVersion) byTimeKey() string {
	b := make([]byte, 0, len(tsFormat)+1+len(cv.Version))
	b = cv.Ctime.AppendFormat(b, tsFormat)
	b = append(b, '#')
	b = append(b, cv.Version...)
	return string(b)
}

// Configuration represents configuration data
type Configuration struct {
	Name   string
	Mtime  time.Time
	Hash   string
	Layers []ComponentVersion
}

// NewConfiguration creates new configuration with given name from provided
// layers. Each layer should belong to different component.
func NewConfiguration(name string, layers ...ComponentVersion) (*Configuration, error) {
	if name == "" || len(layers) == 0 {
		return nil, errors.New("invalid configuration arguments")
	}
	h := sha256.New()
	compSeen := make(map[string]struct{})
	for _, cv := range layers {
		if _, ok := compSeen[cv.Name]; ok {
			return nil, errors.Errorf("duplicate component: %q", cv.Name)
		}
		compSeen[cv.Name] = struct{}{}
		fmt.Fprintf(h, "%s\n", cv.Hash)
	}
	return &Configuration{
		Name:   name,
		Mtime:  time.Now().UTC(),
		Hash:   fmt.Sprintf("%x", h.Sum(nil)),
		Layers: layers,
	}, nil
}

func serveTerminal(tr *tracker, rw io.ReadWriter) error {
	term := terminal.NewTerminal(rw, "> ")
	term.SetPrompt(string(term.Escape.Red) + "> " + string(term.Escape.Reset))
	for {
		line, err := term.ReadLine()
		switch err {
		case nil:
		case io.EOF:
			return nil
		default:
			return err
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if err := tr.handleTerminalCommand(strings.Fields(line)...); err != nil {
			if _, err := fmt.Fprintln(term, err); err != nil {
				return err
			}
		}
	}
}

func (tr *tracker) handleTerminalCommand(args ...string) error {
	if len(args) == 0 {
		return errors.New("nothing to do")
	}
	if args[0] != "deployctl" {
		return errors.Errorf("unknown command: %q", args[0])
	}
	args = args[1:]
	if len(args) == 0 {
		return errors.New("nothing to do")
	}
	subcommand := args[0]
	args = args[1:]
	switch subcommand {
	case "addver":
		err := errors.New("Usage: deployctl addver <component:version> sha256:FILEHASH")
		if len(args) != 2 {
			return err
		}
		var component, version string
		switch flds := strings.SplitN(args[0], ":", 2); {
		case len(flds) != 2:
			return err
		default:
			component, version = flds[0], flds[1]
		}
		return tr.handleAddVersion(component, version, args[1])
	}
	return errors.New("not yet implemented")
}

func (tr *tracker) handleAddVersion(component, version, hash string) error {
	if component == "" || version == "" || len(hash) != len(hashPrefix)+64 ||
		!strings.HasPrefix(hash, hashPrefix) {
		return errors.New("invalid command arguments")
	}
	hash = strings.TrimPrefix(hash, hashPrefix)
	tr.mu.Lock()
	tname, ok := tr.uploads[hash]
	tr.mu.Unlock()
	if !ok {
		return errors.New("no uploaded file with given hash value found")
	}
	cv := &ComponentVersion{
		Name:    component,
		Version: version,
		File:    path.Join(filesDir, hash),
		Hash:    hash,
		Ctime:   time.Now().UTC(),
	}
	if err := os.Rename(tname, filepath.Join(tr.dir, filesDir, hash)); err != nil {
		return err // TODO: don't output real error message here?
	}
	val, err := json.Marshal(cv)
	if err != nil {
		return err
	}
	fn1 := func(tx *bolt.Tx) error {
		return saveTxKey(tx, val, bktComponents, component, bktByVersion, version)
	}
	fn2 := func(tx *bolt.Tx) error {
		return saveTxKey(tx, val, bktComponents, component, bktByTime, cv.byTimeKey())
	}
	if err := multiUpdate(tr.db, fn1, fn2); err != nil {
		return err
	}
	tr.mu.Lock()
	delete(tr.uploads, hash)
	tr.mu.Unlock()
	return nil
}

type exitStatusMsg struct {
	Status uint32
}

func isSftpRequest(req *ssh.Request) bool {
	if req == nil {
		return false
	}
	return req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
}
