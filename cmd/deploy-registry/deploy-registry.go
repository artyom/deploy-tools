// Command deploy-registry implements server for deployment management
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/artyom/autoflags"
	"github.com/artyom/deploy-tools/cmd/deploy-registry/internal/internals"
	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
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
)

func run(args runConf) error {
	hostKey, config, err := internals.ServerSetup(filepath.Join(args.Dir, "id_ecdsa"), args.OpAuth, args.SrvAuth)
	if err != nil {
		return err
	}
	log.Println("host key fingerprint:", ssh.FingerprintSHA256(hostKey.PublicKey()))

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
			_ = conn.SetDeadline(time.Now().Add(time.Minute)) // TODO
			if err := serveConn(conn, config); err != nil {
				log.Println(err)
			}
		}(conn)
	}
}

func serveConn(conn net.Conn, config *ssh.ServerConfig) error {
	defer conn.Close()
	return nil
}

type tracker struct {
	db *bolt.DB
}

// saveKey saves provided value in a boltDB at given address. Address should
// have at least 2 elements, as boltDB does not allow root bucket values. Last
// element of address specifies leaf key. Buckets are created as necessary.
func saveKey(db *bolt.DB, value []byte, addr ...string) error {
	if db == nil || len(value) == 0 || len(addr) < 2 {
		return errors.New("invalid saveKey arguments")
	}
	val := make([]byte, len(value))
	copy(val, value)
	return db.Update(func(tx *bolt.Tx) error {
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
	})
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
		bkt := tx.Bucket([]byte(addr[0]))
		if bkt == nil {
			return nil
		}
		for _, k := range addr[1:] {
			if v := bkt.Get([]byte(k)); v != nil {
				out = make([]byte, len(v))
				copy(out, v)
				return nil
			}
			if bkt = bkt.Bucket([]byte(k)); bkt == nil {
				return nil
			}
		}
		return nil
	})
	return out, errors.WithStack(err)
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

func (cv *ComponentVersion) byTimeKey() []byte {
	b := make([]byte, 0, len(tsFormat)+1+len(cv.Version))
	b = cv.Ctime.AppendFormat(b, tsFormat)
	b = append(b, '#')
	b = append(b, cv.Version...)
	return b
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
