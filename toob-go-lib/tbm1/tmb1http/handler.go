// Package tbm1http is an optional HTTP adapter over the tbm1 encoder.
//
// It is deliberately thin and deliberately separate: the encoder itself has no
// opinion about transport, authentication or tenancy, and most backends will
// want to mount tbm1 behind their own middleware instead of this. Treat this
// file as a worked example — copy it, keep what fits, delete the rest.
//
// Note that Image.InstalledAt (the streaming payload source) cannot cross a
// JSON boundary, so this adapter only exposes the in-memory path. A service
// that handles large firmware should accept an upload, hand the encoder an
// *os.File and never buffer the image at all.
//
// FIX THE IMPORT PATH below to match your module.
package tbm1http

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tbm1"
)

// Options configures a handler. Signer may be nil, which yields a build-only
// node: every key-holding route then answers 501.
type Options struct {
	Signer  tbm1.Signer
	Encoder tbm1.Encoder

	// AuthorizeSign runs after the block has been parsed and before the key is
	// used. Return an error to refuse. This is where a signing node checks that
	// the key index, key epoch and SVN in the block are ones it is allowed to
	// sign — the encoder cannot know that policy.
	AuthorizeSign func(h tbm1.Header) error

	// MaxRequestBytes caps a single JSON body. Zero means 64 MiB.
	MaxRequestBytes int64
}

const defaultMaxRequest = 64 << 20

// New returns a mountable handler:
//
//	POST /v1/package/build  {Manifest}           → {unsigned_block, total_len, signed_len, data_off, stored_len}
//	POST /v1/package/sign   {unsigned_block}     → {signed_block, public_key}   (holds the key)
//	POST /v1/package        {Manifest}           → {signed_block, public_key, total_len, data_off, stored_len}
//	POST /v1/verify         {block, public_key?} → {valid, signature_checked, reason}
//	GET  /v1/pubkey                              → {public_key}
//
// The handler is stateless and safe for concurrent use.
func New(o Options) http.Handler {
	if o.MaxRequestBytes <= 0 {
		o.MaxRequestBytes = defaultMaxRequest
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/package/build", o.handleBuild)
	mux.HandleFunc("/v1/package/sign", o.handleSign)
	mux.HandleFunc("/v1/package", o.handlePackage)
	mux.HandleFunc("/v1/verify", o.handleVerify)
	mux.HandleFunc("/v1/pubkey", o.handlePubkey)
	return recoverPanics(mux)
}

// ---- Responses ----------------------------------------------------------

type buildResponse struct {
	UnsignedBlock []byte   `json:"unsigned_block"`
	TotalLen      uint32   `json:"total_len"`
	SignedLen     uint32   `json:"signed_len"`
	DataOff       []uint32 `json:"data_off"`
	StoredLen     []uint32 `json:"stored_len"`
}

type signResponse struct {
	SignedBlock []byte   `json:"signed_block"`
	PublicKey   []byte   `json:"public_key"`
	TotalLen    uint32   `json:"total_len,omitempty"`
	DataOff     []uint32 `json:"data_off,omitempty"`
	StoredLen   []uint32 `json:"stored_len,omitempty"`
}

type verifyResponse struct {
	Valid bool `json:"valid"`
	// SignatureChecked is false when no key was available; Valid then means
	// "structurally sound" only. Clients must not read that as authenticated.
	SignatureChecked bool   `json:"signature_checked"`
	Reason           string `json:"reason,omitempty"`
}

type pubkeyResponse struct {
	PublicKey []byte `json:"public_key"`
}

// ---- Handlers -----------------------------------------------------------

func (o Options) handleBuild(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var m tbm1.Manifest
	if !o.decode(w, r, &m) {
		return
	}
	pkg, err := o.Encoder.BuildUnsigned(m)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, buildResponse{
		UnsignedBlock: pkg.Block,
		TotalLen:      pkg.TotalLen,
		SignedLen:     pkg.SignedLen,
		DataOff:       pkg.DataOff,
		StoredLen:     pkg.StoredLen,
	})
}

func (o Options) handleSign(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !o.requireSigner(w) {
		return
	}
	var req struct {
		UnsignedBlock []byte `json:"unsigned_block"`
	}
	if !o.decode(w, r, &req) {
		return
	}
	if !o.authorize(w, req.UnsignedBlock) {
		return
	}
	signed, err := tbm1.SignBlock(req.UnsignedBlock, o.Signer)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, signResponse{
		SignedBlock: signed,
		PublicKey:   o.Signer.Public(),
	})
}

func (o Options) handlePackage(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !o.requireSigner(w) {
		return
	}
	var m tbm1.Manifest
	if !o.decode(w, r, &m) {
		return
	}
	pkg, err := o.Encoder.BuildUnsigned(m)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !o.authorize(w, pkg.Block) {
		return
	}
	if err := pkg.Sign(o.Signer); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, signResponse{
		SignedBlock: pkg.Block,
		PublicKey:   o.Signer.Public(),
		TotalLen:    pkg.TotalLen,
		DataOff:     pkg.DataOff,
		StoredLen:   pkg.StoredLen,
	})
}

func (o Options) handleVerify(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Block     []byte `json:"block"`
		PublicKey []byte `json:"public_key,omitempty"`
	}
	if !o.decode(w, r, &req) {
		return
	}
	pub := ed25519.PublicKey(req.PublicKey)
	if len(pub) == 0 && o.Signer != nil {
		pub = o.Signer.Public()
	}

	var resp verifyResponse
	switch {
	case len(pub) != 0 && len(pub) != ed25519.PublicKeySize:
		writeErr(w, fmt.Errorf("%w: public_key must be %d bytes", tbm1.ErrInvalidManifest, ed25519.PublicKeySize))
		return
	case len(pub) == ed25519.PublicKeySize:
		resp.SignatureChecked = true
		if err := tbm1.VerifyBlock(req.Block, pub); err != nil {
			resp.Reason = err.Error()
		} else {
			resp.Valid = true
		}
	default: // no key anywhere: structure only
		if err := tbm1.ValidateBlock(req.Block); err != nil {
			resp.Reason = err.Error()
		} else {
			resp.Valid = true
			resp.Reason = "structure only — no public key available, signature not checked"
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (o Options) handlePubkey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !o.requireSigner(w) {
		return
	}
	writeJSON(w, http.StatusOK, pubkeyResponse{PublicKey: o.Signer.Public()})
}

// authorize applies the caller's signing policy to a block. A parse failure is
// reported as a client error; a policy rejection as 403.
func (o Options) authorize(w http.ResponseWriter, block []byte) bool {
	if o.AuthorizeSign == nil {
		return true
	}
	h, err := tbm1.ParseHeader(block)
	if err != nil {
		writeErr(w, err)
		return false
	}
	if err := o.AuthorizeSign(h); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return false
	}
	return true
}

// ---- Plumbing -----------------------------------------------------------

// guardedWriter remembers whether the status line already went out, so the
// panic handler knows if it can still produce a clean 500.
type guardedWriter struct {
	http.ResponseWriter
	wrote bool
}

func (g *guardedWriter) WriteHeader(status int) {
	g.wrote = true
	g.ResponseWriter.WriteHeader(status)
}

func (g *guardedWriter) Write(b []byte) (int, error) {
	g.wrote = true
	return g.ResponseWriter.Write(b)
}

// recoverPanics keeps one bad request from taking the signing service down.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := &guardedWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil && !g.wrote {
				writeJSON(g, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(g, r)
	})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": method + " only"})
		return false
	}
	return true
}

func (o Options) requireSigner(w http.ResponseWriter) bool {
	if o.Signer == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": tbm1.ErrNoSigner.Error()})
		return false
	}
	return true
}

func (o Options) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType,
				map[string]string{"error": "expected Content-Type: application/json"})
			return false
		}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, o.MaxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body: " + err.Error()})
		return false
	}
	if dec.More() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unexpected data after the JSON body"})
		return false
	}
	return true
}

// writeJSON encodes into a buffer first, so an encoding failure cannot leave a
// half-written body behind a 200 status line.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, `{"error":"response encoding failed"}`, http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// writeErr maps library errors onto status codes: anything the caller can fix
// is a 400, everything else (signer or KMS trouble) a 500.
func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, tbm1.ErrInvalidManifest),
		errors.Is(err, tbm1.ErrMalformedBlock),
		errors.Is(err, tbm1.ErrLayoutOverflow),
		errors.Is(err, tbm1.ErrPayload),
		errors.Is(err, tbm1.ErrUnsigned):
		status = http.StatusBadRequest
	case errors.Is(err, tbm1.ErrNoSigner):
		status = http.StatusNotImplemented
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
