package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openweir/openwrt/internal/kernel"
	"github.com/openweir/openwrt/internal/tlsdiag"
	"golang.org/x/sys/unix"
)

const uploadRoot = "/tmp/openweir-upload"
const maxUploadBytes = 512 << 20

func validUpload(id string) bool {
	_, err := hex.DecodeString(id)
	return err == nil && len(id) == 24
}
func prepareUpload(body json.RawMessage) (any, error) {
	var req struct {
		Bytes  int64  `json:"bytes"`
		Remove string `json:"remove"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if !json.Valid(body) || dec.Decode(&req) != nil || req.Remove != "" && req.Bytes != 0 {
		return nil, errors.New("invalid upload request")
	}
	if err := os.MkdirAll(uploadRoot, 0700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(uploadRoot)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private upload storage unavailable")
	}
	if req.Remove != "" {
		if !validUpload(req.Remove) {
			return nil, errors.New("invalid upload identifier")
		}
		return map[string]bool{"removed": true}, os.RemoveAll(filepath.Join(uploadRoot, req.Remove))
	}
	if req.Bytes <= 0 || req.Bytes > maxUploadBytes {
		return nil, errors.New("invalid release archive size")
	}
	var st unix.Statfs_t
	if err := unix.Statfs(uploadRoot, &st); err != nil {
		return nil, err
	}
	if uint64(st.Bavail)*uint64(st.Bsize) < uint64(req.Bytes+(12<<20)) {
		return nil, errors.New("insufficient upload space")
	}
	dirs, err := os.ReadDir(uploadRoot)
	if err != nil {
		return nil, err
	}
	active := 0
	for _, d := range dirs {
		if validUpload(d.Name()) {
			info, e := d.Info()
			if e != nil {
				return nil, e
			}
			if time.Since(info.ModTime()) > time.Hour {
				if e = os.RemoveAll(filepath.Join(uploadRoot, d.Name())); e != nil {
					return nil, e
				}
			} else {
				active++
			}
		}
	}
	if active >= 2 {
		return nil, errors.New("another release upload is in progress")
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	key := hex.EncodeToString(id)
	path := filepath.Join(uploadRoot, key)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	return map[string]string{"id": key, "path": path}, nil
}
func transientBundle(path string) bool {
	return filepath.Clean(path) == path && filepath.Dir(path) == uploadRoot && validUpload(filepath.Base(path))
}

// LuCI may choose a transport, but only the installer may choose trusted metadata.
func checkKernelArgs(action string, args map[string]json.RawMessage) (string, error) {
	for key := range args {
		switch {
		case (action == "select" || action == "install-json") && key == "tag":
		case action == "install-json" && (key == "mode" || key == "bundle" || key == "url" || key == "mirror"):
		default:
			return "", errors.New("unsupported kernel request field")
		}
	}
	raw, ok := args["bundle"]
	if !ok {
		return "", nil
	}
	var dir, mode string
	if json.Unmarshal(raw, &dir) != nil || !transientBundle(dir) {
		return "", errors.New("expected the private directory of a release upload")
	}
	if rawMode, ok := args["mode"]; ok && (json.Unmarshal(rawMode, &mode) != nil || mode == "tmp") {
		return "", errors.New("an uploaded archive requires persistent kernel storage")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return "", errors.New("release upload is unavailable")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".gz") {
		return "", errors.New("expected one original release archive")
	}
	file, err := entries[0].Info()
	if err != nil || !file.Mode().IsRegular() || file.Size() <= 0 || file.Size() > maxUploadBytes {
		return "", errors.New("invalid release archive")
	}
	return dir, nil
}

// Never forward raw helper stderr: file paths and mirror URLs can contain secrets.
func publicKernelError(stderr string) error {
	message := strings.TrimSpace(stderr)
	if failure := tlsdiag.Parse(message); failure != nil {
		return errors.New(failure.Wire())
	}
	switch message {
	case errKernelRevision.Error():
		return errKernelRevision
	case kernel.ErrReleaseRateLimit.Error():
		return kernel.ErrReleaseRateLimit
	case kernel.ErrTemporaryDownload.Error():
		return kernel.ErrTemporaryDownload
	case "publisher has no stable release":
		return errors.New("publisher has no stable release")
	case "latest stable release unreachable", "invalid latest stable release identity", "latest stable release lacks a verified archive for this router":
		return errors.New(message)
	case "release file size or SHA-256 mismatch", "archive was modified during extraction":
		return errors.New("release checksum mismatch")
	case "invalid or ambiguous upstream checksum", "upstream checksum is missing for this architecture",
		"invalid original release asset digest", "original release supplies no SHA-256 for this archive":
		return errors.New("upstream release checksum unavailable")
	case "original release lacks a matching Linux CLI archive", "invalid Linux ELF",
		"wrong ELF machine, class or endian", "core OS/architecture mismatch",
		"core instruction set exceeds the declared target", "wrong ARM instruction or floating-point ABI",
		"wrong software floating-point ABI":
		return errors.New("release archive incompatible with this router")
	case "release source unreachable":
		return errors.New("release source unreachable")
	case "core failed restricted version validation", "Mihomo executable reported a different version":
		return errors.New("release executable failed version validation")
	case "insufficient free storage; active core retained", "insufficient shared storage; active core retained",
		"insufficient temporary space for release archive", "insufficient space on cache volume",
		"insufficient trial RAM and 48 MiB system reserve", "persistent mode requires 128 MiB storage and 256 MiB RAM",
		"temporary mode requires 64 MiB storage and 512 MiB RAM":
		return errors.New("insufficient resources for this storage mode")
	}
	if strings.HasPrefix(message, "cannot verify original release via GitHub: ") || strings.HasPrefix(message, "original release checksum unavailable: ") {
		return errors.New("upstream release checksum unavailable")
	}
	return errors.New("kernel operation failed")
}
