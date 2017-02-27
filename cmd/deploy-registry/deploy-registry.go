// Command deploy-registry implements server for deployment management
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/artyom/autoflags"
	"github.com/artyom/deploy-tools/cmd/deploy-registry/internal/internals"
	"github.com/boltdb/bolt"
	shellwords "github.com/mattn/go-shellwords"
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
	filesDir  = "files"
	uploadDir = "uploads"

	bktByVersion  = "byVersion"
	bktByTime     = "byTime"
	bktComponents = "components"
	bktConfigs    = "configs"
	bktFiles      = "files"
	keyCurrent    = "current"
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
	var width, height int // terminal dimensions, updated by pty-req
	for req := range requests {
		var ok bool
		switch {
		case req.Type == "pty-req":
			// TODO: handle "window-change" as well
			width, height = ptyRequestDimensions(req.Payload)
			req.Reply(true, nil)
			continue
		case req.Type == "shell":
			ok = true
			go func() {
				defer sshCh.Close()      // SSH_MSG_CHANNEL_CLOSE
				defer sshCh.CloseWrite() // SSH_MSG_CHANNEL_EOF
				defer sshCh.SendRequest("eow@openssh.com", false, nil)
				switch err := serveTerminal(tr, width, height, sshCh); err {
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
	// files holds references to open files from filesDir
	files map[string]ReaderAtCloser

	st *syscall.Stat_t // used to attach to virtual files
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
	data, err := fetchKey(tr.db, bktConfigs, name, keyCurrent)
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

func (tr *tracker) openFile(base string) (ReaderAtCloser, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	r, ok := tr.files[base]
	if ok {
		return r, nil
	}
	f, err := os.Open(filepath.Join(tr.dir, filesDir, base))
	if err != nil {
		return nil, err
	}
	r = &openFile{f: f, closeCallback: func() {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		delete(tr.files, base)
	}}
	tr.files[base] = r
	return f, nil
}

func (tr *tracker) fileReadFunc(r sftp.Request) (io.ReaderAt, error) {
	rPath := path.Clean(r.Filepath)
	if ok, err := path.Match("/files/?*", rPath); ok && err == nil {
		return tr.openFile(path.Base(rPath))
	}
	if ok, err := path.Match("/configs/?*.json", rPath); ok && err == nil {
		return tr.openConfig(strings.TrimSuffix(path.Base(rPath), ".json"))
	}
	return nil, syscall.ENOENT
}

func (tr *tracker) openConfig(name string) (io.ReaderAt, error) {
	data, err := fetchKey(tr.db, bktConfigs, name, keyCurrent)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, syscall.ENOENT
	}
	return bytes.NewReader(data), nil
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
		files:   make(map[string]ReaderAtCloser),
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
		if bkt, err = bkt.CreateBucketIfNotExists([]byte(k)); err != nil {
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
			if val := fetchTxKey(tx, bktConfigs, k, keyCurrent); val != nil {
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

func (cv *ComponentVersion) byTimeKey() string {
	b := make([]byte, 0, len(time.RFC3339)+1+len(cv.Version))
	b = cv.Ctime.AppendFormat(b, time.RFC3339)
	b = append(b, '#')
	b = append(b, cv.Version...)
	return string(b)
}

func (cv *ComponentVersion) save(tx *bolt.Tx) error {
	val, err := json.Marshal(cv)
	if err != nil {
		return err
	}
	err = saveTxKey(tx, val, bktComponents, cv.Name, bktByVersion, cv.Version)
	if err != nil {
		return err
	}
	err = saveTxKey(tx, val, bktComponents, cv.Name, bktByTime, cv.byTimeKey())
	if err != nil {
		return err
	}
	return addFileReference(tx, cv.Hash, fileReference{
		Component: cv.Name,
		Version:   cv.Version,
	})
}

// Configuration represents configuration data
type Configuration struct {
	Name   string
	Mtime  time.Time
	Hash   string
	Layers []*ComponentVersion
}

func (cfg *Configuration) tsKey() string {
	const prefixLen = 5
	b := make([]byte, 0, len(time.RFC3339)+1+prefixLen)
	b = cfg.Mtime.AppendFormat(b, time.RFC3339)
	b = append(b, '#')
	b = append(b, cfg.Hash[:prefixLen]...)
	return string(b)
}

// replaceLayer replaces existing layer in configuration with new one, updating
// configuration Mtime and Hash as necessary. Configuration is only updated if
// matching layer to replace is found, otherwise error is returned.
func (cfg *Configuration) replaceLayer(cv *ComponentVersion) error {
	var found bool
	h := sha256.New()
	for i, cv2 := range cfg.Layers {
		switch {
		case cv2.Name == cv.Name:
			cfg.Layers[i] = cv
			found = true
			fmt.Fprintf(h, "%s\n", cv.Hash)
		default:
			fmt.Fprintf(h, "%s\n", cv2.Hash)
		}
	}
	if !found {
		return errors.Errorf("configuration has no layer for component %q", cv.Name)
	}
	cfg.Mtime = time.Now().UTC()
	cfg.Hash = fmt.Sprintf("%x", h.Sum(nil))
	return nil
}

// save marshals configuration and saves it to "current" and timestamp-based
// keys using provided transaction
func (cfg *Configuration) save(tx *bolt.Tx) error {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "\t")
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := saveTxKey(tx, buf.Bytes(), bktConfigs, cfg.Name, keyCurrent); err != nil {
		return err
	}
	return saveTxKey(tx, buf.Bytes(), bktConfigs, cfg.Name, cfg.tsKey())
}

// NewConfiguration creates new configuration with given name from provided
// layers. Each layer should belong to different component.
func NewConfiguration(name string, layers ...*ComponentVersion) (*Configuration, error) {
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

func getComponentVersion(db *bolt.DB, component, version string) (*ComponentVersion, error) {
	data, err := fetchKey(db, bktComponents, component, bktByVersion, version)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.Errorf("no version %q for component %q found", version, component)
	}
	var cv ComponentVersion
	if err := json.Unmarshal(data, &cv); err != nil {
		return nil, err
	}
	return &cv, nil
}

func getConfiguration(db *bolt.DB, name string) (*Configuration, error) {
	var cfg *Configuration
	err := db.View(func(tx *bolt.Tx) error {
		c, err := getTxConfiguration(tx, name)
		cfg = c
		return err
	})
	return cfg, err
}

func getTxConfiguration(tx *bolt.Tx, name string) (*Configuration, error) {
	data := fetchTxKey(tx, bktConfigs, name, keyCurrent)
	if data == nil {
		return nil, errors.Errorf("configuration %q not found", name)
	}
	var conf Configuration
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}

func getTxComponentVersion(tx *bolt.Tx, component, version string) (*ComponentVersion, error) {
	data := fetchTxKey(tx, bktComponents, component, bktByVersion, version)
	if data == nil {
		return nil, errors.Errorf("no version %q for component %q found", version, component)
	}
	var cv ComponentVersion
	if err := json.Unmarshal(data, &cv); err != nil {
		return nil, err
	}
	return &cv, nil
}

func serveTerminal(tr *tracker, width, height int, rw io.ReadWriter) error {
	term := terminal.NewTerminal(rw, "> ")
	if width > 0 && height > 0 {
		_ = term.SetSize(width, height)
	}
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
		args, err := shellwords.Parse(line)
		if err != nil {
			fmt.Fprintln(term, err)
			continue
		}
		if err := tr.handleTerminalCommand(term, args); err != nil {
			fmt.Fprintln(term, err)
		}
	}
}

func (tr *tracker) handleTerminalCommand(term io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("nothing to do")
	}
	switch cmd, args := args[0], args[1:]; cmd {
	case "help":
		fmt.Fprintln(term, strings.TrimSpace(verboseHelp))
		return nil
	case "addver":
		return tr.handleAddVersion(term, args)
	case "addconf":
		return tr.handleAddConfiguration(term, args)
	case "changeconf":
		return tr.handleUpdateConfiguration(term, args)
	case "showconf":
		return tr.handleShowConfiguration(term, args)
	case "showcomp":
		return tr.handleShowComponent(term, args)
	case "components":
		return tr.handleShowBucketKeys(term, bktComponents)
	case "configurations":
		return tr.handleShowBucketKeys(term, bktConfigs)
	}
	knownCommands := []string{"help", "addver", "addconf",
		"changeconf", "showconf",
		"components", "configurations",
		"showcomp",
	}
	fmt.Fprintln(term, "Unknown command, supported commands are:")
	fmt.Fprintln(term, strings.Join(knownCommands, ", "))
	return nil
}

func (tr *tracker) handleShowBucketKeys(w io.Writer, bucketAddr ...string) error {
	var keys []string
	err := tr.db.View(func(tx *bolt.Tx) error {
		keys = fetchTxBucketKeys(tx, bucketAddr...)
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range keys {
		fmt.Fprintln(w, name)
	}
	return nil
}

func (tr *tracker) handleShowComponent(w io.Writer, rawArgs []string) error {
	args := struct {
		Name string `flag:"name,component name"`
	}{}
	fs := flag.NewFlagSet("showcomp", flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, &args)
	if fs.Parse(rawArgs) != nil {
		return nil // flagset already wrote error to term
	}
	if args.Name == "" {
		return errors.New("invalid command arguments")
	}
	var keys []string
	err := tr.db.View(func(tx *bolt.Tx) error {
		keys = fetchTxBucketKeys(tx, bktComponents, args.Name, bktByTime)
		return nil
	})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 8, 1, '\t', 0)
	for _, name := range keys {
		fmt.Fprintln(tw, strings.Replace(name, "#", "\t", 1))
	}
	return tw.Flush()
}

func (tr *tracker) handleShowConfiguration(w io.Writer, rawArgs []string) error {
	args := struct {
		Name    string `flag:"name,configuration name"`
		Verbose bool   `flag:"v,show extra details"`
	}{}
	fs := flag.NewFlagSet("showconf", flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, &args)
	if fs.Parse(rawArgs) != nil {
		return nil // flagset already wrote error to term
	}
	if args.Name == "" {
		return errors.New("invalid command arguments")
	}
	cfg, err := getConfiguration(tr.db, args.Name)
	if err != nil {
		return err
	}
	if args.Verbose {
		fmt.Fprintf(w, "Name:\t%s\n", cfg.Name)
		fmt.Fprintf(w, "Mtime:\t%s\n", cfg.Mtime.Format(time.RFC3339))
		fmt.Fprintf(w, "Hash:\t%s\n", cfg.Hash)
		fmt.Fprintln(w)
	}
	tw := tabwriter.NewWriter(w, 0, 8, 1, '\t', 0)
	for _, l := range cfg.Layers {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", l.Name, l.Version,
			l.Ctime.Format(time.RFC3339))
	}
	return tw.Flush()
}

func (tr *tracker) handleUpdateConfiguration(w io.Writer, rawArgs []string) error {
	args := struct {
		Name string `flag:"name,configuration name"`
		Comp string `flag:"component,component name to update"`
		Ver  string `flag:"version,new version of selected component"`
	}{}
	fs := flag.NewFlagSet("changeconf", flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, &args)
	if fs.Parse(rawArgs) != nil {
		return nil // flagset already wrote error to term
	}
	if args.Name == "" || args.Comp == "" || args.Ver == "" {
		return errors.New("invalid command arguments")
	}
	fn := func(tx *bolt.Tx) error {
		cv, err := getTxComponentVersion(tx, args.Comp, args.Ver)
		if err != nil {
			return err
		}
		cfg, err := getTxConfiguration(tx, args.Name)
		if err != nil {
			return err
		}
		if err := cfg.replaceLayer(cv); err != nil {
			return err
		}
		return cfg.save(tx)
	}
	return multiUpdate(tr.db, fn)
}

func (tr *tracker) handleAddConfiguration(w io.Writer, rawArgs []string) error {
	args := struct {
		Name   string       `flag:"name,configuration name"`
		Layers compVerSlice `flag:"layer,layer in component:version format; can be set multiple times"`
	}{}
	fs := flag.NewFlagSet("addconf", flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, &args)
	if fs.Parse(rawArgs) != nil {
		return nil // flagset already wrote error to term
	}
	if args.Name == "" || len(args.Layers) == 0 {
		return errors.New("invalid command arguments")
	}
	var layers []*ComponentVersion
	for _, l := range args.Layers {
		cv, err := getComponentVersion(tr.db, l.comp, l.ver)
		if err != nil {
			return err
		}
		layers = append(layers, cv)
	}
	cfg, err := NewConfiguration(args.Name, layers...)
	if err != nil {
		return err
	}
	return multiUpdate(tr.db, cfg.save)
}

func (tr *tracker) handleAddVersion(w io.Writer, rawArgs []string) error {
	args := struct {
		Name    string `flag:"name,component name"`
		Version string `flag:"version,unique version id"`
		Hash    string `flag:"hash,sha256 content hash in hex representation (64 chars)"`
	}{}
	fs := flag.NewFlagSet("addver", flag.ContinueOnError)
	fs.SetOutput(w)
	autoflags.DefineFlagSet(fs, &args)
	if fs.Parse(rawArgs) != nil {
		return nil // flagset already wrote error to term
	}
	if args.Name == "" || args.Version == "" || args.Hash == "" {
		return errors.New("invalid command arguments")
	}
	if strings.ContainsRune(args.Name, ':') {
		return errors.New("component name cannot contain ':'")
	}
	if len(args.Hash) != 64 {
		return errors.New("invalid hash specification")
	}
	tr.mu.Lock()
	tname, ok := tr.uploads[args.Hash]
	tr.mu.Unlock()
	if !ok {
		return errors.New("no uploaded file with given hash found")
	}
	cv := &ComponentVersion{
		Name:    args.Name,
		Version: args.Version,
		File:    path.Join(filesDir, args.Hash),
		Hash:    args.Hash,
		Ctime:   time.Now().UTC(),
	}
	if err := os.Rename(tname, filepath.Join(tr.dir, filesDir, args.Hash)); err != nil {
		return err // TODO: don't output real error message here?
	}
	if err := multiUpdate(tr.db, cv.save); err != nil {
		return err
	}
	tr.mu.Lock()
	delete(tr.uploads, args.Hash)
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

type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

// openFile implements io.ReaderAt, io.Closer
type openFile struct {
	f             *os.File
	once          sync.Once
	closeCallback func()
}

func (of *openFile) ReadAt(p []byte, off int64) (int, error) { return of.f.ReadAt(p, off) }
func (of *openFile) Close() error {
	of.once.Do(of.closeCallback)
	return of.f.Close()
}

// compVer holds single layer specification as passed by operator
type compVer struct {
	comp, ver string
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
		if v.comp == flds[0] {
			return errors.Errorf("duplicate component %q", flds[0])
		}
	}
	*c = append(*c, compVer{comp: flds[0], ver: flds[1]})
	return nil
}

// ptyRequestDimensions parses "pty-req" request payload as specified in
// RFC4254, section 6.2 and returns width and height. In case of errors zero
// values are returned.
func ptyRequestDimensions(b []byte) (width, height int) {
	if len(b) < 4 {
		return 0, 0
	}
	termLen := int(b[3]) // TERM variable size
	if len(b) <= 3+1+termLen+4*2 {
		return 0, 0
	}
	b = b[3+1+termLen:]
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return int(w), int(h)
}

// fileReference describes single component version which references file
type fileReference struct {
	Component, Version string
}

func addFileReference(tx *bolt.Tx, hash string, ref fileReference) error {
	var references []fileReference
	if data := fetchTxKey(tx, bktFiles, hash); data != nil {
		if err := json.Unmarshal(data, &references); err != nil {
			return err
		}
	}
	for _, r := range references {
		if r == ref {
			return nil
		}
	}
	references = append(references, ref)
	data, err := json.Marshal(references)
	if err != nil {
		return err
	}
	return saveTxKey(tx, data, bktFiles, hash)
}

const verboseHelp = `
addver          add new component version from previously uploaded file
addconf         add new configuration from existing component versions
changeconf      update single layer in existing configuration
showconf        show configuration
showcomp        show component versions
components      show list of all known components
configurations  show list of all known configurations

type "command -h" to get more help on a specific command
`
