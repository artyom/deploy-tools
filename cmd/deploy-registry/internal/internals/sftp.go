package internals

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
)

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

type FileInfoFunc func(sftp.Request) ([]os.FileInfo, error)
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
	f, err := ioutil.TempFile(dir, "upload-")
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
