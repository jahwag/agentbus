// Package credentialfile reads bearer credentials under a single filesystem
// policy shared by the daemon and CLI.
package credentialfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Read returns a bounded credential from either an ordinary owner-only file or
// a systemd LoadCredential mount. systemd 255 presents service-user
// credentials as 0440 inside a private 0550 directory and grants access with a
// mount ACL; that narrow case is safe even though a raw group bit is present.
func Read(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxBytes {
		return nil, fmt.Errorf("credential must be a regular file no larger than %d bytes", maxBytes)
	}
	if !protected(path, before.Mode().Perm()) {
		return nil, errors.New("credential file permissions expose the credential")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > maxBytes {
		return nil, errors.New("credential file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("credential exceeds %d-byte limit", maxBytes)
	}
	return raw, nil
}

func protected(path string, perm os.FileMode) bool {
	// Ordinary secret files may have only owner read/write bits.
	if perm&0o177 == 0 {
		return true
	}
	// The only exception is the exact systemd credential shape under the
	// directory systemd explicitly passes to the service.
	if perm != 0o400 && perm != 0o440 {
		return false
	}
	credentialDir := os.Getenv("CREDENTIALS_DIRECTORY")
	if credentialDir == "" || !filepath.IsAbs(credentialDir) || !filepath.IsAbs(path) {
		return false
	}
	credentialDir = filepath.Clean(credentialDir)
	if filepath.Dir(filepath.Clean(path)) != credentialDir {
		return false
	}
	dirInfo, err := os.Lstat(credentialDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o027 != 0 {
		return false
	}
	return true
}
