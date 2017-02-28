package internals

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

// UploadPrefix is used when creating temporary files to save uploads to
const UploadPrefix = "upload-"

// NewUploadServer returns sftp.RequestServer that only handles file uploads
// (put requests) using newUploadHandlers.
func NewUploadServer(rwc io.ReadWriteCloser, dir string, callback func(name, hash string)) *sftp.RequestServer {
	return sftp.NewRequestServer(rwc, newUploadHandlers(dir, callback))
}

// newUploadHandlers returns sftp.Handlers that only handles file uploads. It
// saves files to temporary directory dir and automatically calculates file
// hashes after they're closed. After file is uploaded, callback function is
// called with the name of the file and hex representation of file sha256 hash.
func newUploadHandlers(dir string, callback func(name, hash string)) sftp.Handlers {
	h := &uploadHandler{
		uploads:  dir,
		callback: callback,
	}
	return sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileInfo: h,
	}
}

type uploadHandler struct {
	uploads  string
	callback func(name, hash string)
}

func (h *uploadHandler) Filecmd(r sftp.Request) error                   { return syscall.EPERM }
func (h *uploadHandler) Fileinfo(r sftp.Request) ([]os.FileInfo, error) { return nil, syscall.EPERM }
func (h *uploadHandler) Fileread(r sftp.Request) (io.ReaderAt, error)   { return nil, syscall.EPERM }
func (h *uploadHandler) Filewrite(r sftp.Request) (io.WriterAt, error) {
	return newWriterAt(h.uploads, h.callback)
}

// NewDownloadServer returns read-only sftp.RequestServer that processes get
// requests with provided FileReadFunc and list, stat, readlink requests using
// provided FileInfoFunc.
func NewDownloadServer(rwc io.ReadWriteCloser, ifn FileInfoFunc, rfn FileReadFunc) *sftp.RequestServer {
	return sftp.NewRequestServer(rwc, newDownloadHandlers(ifn, rfn))
}

func newDownloadHandlers(ifn FileInfoFunc, rfn FileReadFunc) sftp.Handlers {
	h := &downloadHandler{
		fileInfoFunc: ifn,
		fileReadFunc: rfn,
	}
	return sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileInfo: h,
	}
}

type downloadHandler struct {
	fileInfoFunc FileInfoFunc
	fileReadFunc FileReadFunc
}

func (h *downloadHandler) Filecmd(r sftp.Request) error                   { return syscall.EPERM }
func (h *downloadHandler) Fileinfo(r sftp.Request) ([]os.FileInfo, error) { return h.fileInfoFunc(r) }
func (h *downloadHandler) Fileread(r sftp.Request) (io.ReaderAt, error)   { return h.fileReadFunc(r) }
func (h *downloadHandler) Filewrite(r sftp.Request) (io.WriterAt, error)  { return nil, syscall.EPERM }

// FileInfoFunc is a function from sftp.FileInfoer interface
type FileInfoFunc func(sftp.Request) ([]os.FileInfo, error)

// FileReadFunc is a function from sftp.FileReader interface
type FileReadFunc func(sftp.Request) (io.ReaderAt, error)

// newWriterAt creates temporary file in a given directory and returns
// io.WriterAt which also implements io.Closer, which calculates file sha256
// hash on close and calls callback function with file name and string
// replresentation of calculated sum. As it has to read file on Close() call, it
// takes some time.
//
// This is intended for sftp.FileWriter interface impementations that want to
// calculate hash of uploaded file.
func newWriterAt(dir string, callback func(name, hash string)) (io.WriterAt, error) {
	_ = os.MkdirAll(dir, 0700)
	f, err := ioutil.TempFile(dir, UploadPrefix)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &fileHasher{f, callback}, nil
}

type fileHasher struct {
	f        *os.File
	callback func(name, hash string)
}

func (fh *fileHasher) WriteAt(p []byte, off int64) (int, error) { return fh.f.WriteAt(p, off) }
func (fh *fileHasher) Close() error {
	x, err := fileHash(fh.f)
	if err != nil {
		fh.f.Close()
		return err
	}
	fh.callback(fh.f.Name(), fmt.Sprintf("%x", x))
	return errors.WithStack(fh.f.Close())
}

func fileHash(f io.ReadSeeker) ([]byte, error) {
	if _, err := f.Seek(0, os.SEEK_SET); err != nil {
		return nil, errors.WithStack(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, errors.WithStack(err)
	}
	return h.Sum(nil), nil
}

// SftpFile combines interfaces required for sftp virtual file implementations
type SftpFile interface {
	os.FileInfo
	io.ReaderAt
}

// file implements both os.FileInfo and io.ReaderAt interfaces
type file struct {
	name  string
	bytes []byte
	rdat  io.ReaderAt
	mode  os.FileMode
	time  time.Time
	sys   *syscall.Stat_t
}

// NewFile creates new virtual file
func NewFile(name string, dir bool, mtime time.Time, data []byte, sys *syscall.Stat_t) SftpFile {
	f := &file{
		name: filepath.Base(name),
		time: mtime,
		sys:  sys,
		mode: os.FileMode(0750) | os.ModeDir,
	}
	if !dir {
		f.mode = os.FileMode(0644)
		f.bytes = data
		f.rdat = bytes.NewReader(data)
	}
	return f
}

func (f *file) Name() string       { return f.name }
func (f *file) Size() int64        { return int64(len(f.bytes)) }
func (f *file) Mode() os.FileMode  { return f.mode }
func (f *file) ModTime() time.Time { return f.time }
func (f *file) IsDir() bool        { return f.mode.IsDir() }
func (f *file) Sys() interface{}   { return f.sys }

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	if f.rdat == nil || f.mode.IsDir() {
		return 0, os.ErrInvalid
	}
	return f.rdat.ReadAt(p, off)
}
