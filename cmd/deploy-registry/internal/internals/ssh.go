package internals

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type keyMeta struct {
	key  ssh.PublicKey
	opts map[string]string
}

func readAuthorizedKeys(name string) ([]keyMeta, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer f.Close()
	var keys []keyMeta
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pk, _, opts, _, err := ssh.ParseAuthorizedKey(sc.Bytes())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		keys = append(keys, keyMeta{key: pk, opts: splitOpts(opts)})
	}
	if err := sc.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	if len(keys) == 0 {
		return nil, errors.Errorf("file %q should have at least one key", name)
	}
	return keys, nil
}

const serviceUserName = "deploy-agent"

func AuthChecker(opAuth, srvAuth string) (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), error) {
	opAuthKeys, err := readAuthorizedKeys(opAuth)
	if err != nil {
		return nil, err
	}
	srvAuthKeys, err := readAuthorizedKeys(srvAuth)
	if err != nil {
		return nil, err
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyBytes := key.Marshal()
		pkeys := opAuthKeys
		var critOpts map[string]string
		if conn.User() == serviceUserName {
			pkeys = srvAuthKeys
			critOpts = map[string]string{serviceUserName: ""}
		}
		for _, k := range pkeys {
			if bytes.Equal(keyBytes, k.key.Marshal()) {
				return &ssh.Permissions{
					CriticalOptions: critOpts,
					Extensions:      k.opts,
				}, nil
			}
		}
		return nil, errors.Errorf("no keys matched")
	}, nil
}

func IsServiceUser(p *ssh.Permissions) bool {
	_, ok := p.CriticalOptions[serviceUserName]
	return ok
}

func splitOpts(opts []string) map[string]string {
	if len(opts) == 0 {
		return nil
	}
	m := make(map[string]string, len(opts))
	for _, s := range opts {
		ss := strings.SplitN(s, "=", 2)
		switch len(ss) {
		case 1:
			m[s] = ""
		case 2:
			m[ss[0]] = ss[1]
		}
	}
	return m
}

// HostKey reads private key from disk or creates it if necessary
func HostKey(name string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(name)
	switch {
	case err == nil:
		return ssh.ParsePrivateKey(privateBytes)
	case os.IsNotExist(err):
	default:
		return nil, errors.WithStack(err)
	}
	privateBytes, err = generatePrivateKey()
	if err != nil {
		return nil, err
	}
	if err := writePrivateKey(name, privateBytes); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func generatePrivateKey() ([]byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes}), nil
}

func writePrivateKey(name string, pemBytes []byte) error {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()
	if _, err := f.Write(pemBytes); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(f.Close())
}

// ServerSetup reads provided both authorized_keys files located at opAuth and
// srvAuth, reads or creates private key from keyFile and sets up
// ssh.ServerConfig using public key authentication.
func ServerSetup(keyFile, opAuth, srvAuth string) (ssh.Signer, *ssh.ServerConfig, error) {
	publicKeyCallback, err := AuthChecker(opAuth, srvAuth)
	if err != nil {
		return nil, nil, err
	}
	hostKey, err := HostKey(keyFile)
	if err != nil {
		return nil, nil, err
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: publicKeyCallback,
		ServerVersion:     "SSH-2.0-generic",
	}
	config.AddHostKey(hostKey)
	return hostKey, config, nil
}
