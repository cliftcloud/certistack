// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package screendump captures virtual machine console framebuffers upon test failure for forensic triage.
package screendump

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/probe/qmp"
)

// Artifact represents a captured and converted console screenshot.
type Artifact struct {
	// PPMPath is the raw frame QEMU wrote. Capture removes it before it
	// returns, so it is only where the frame was.
	PPMPath string `json:"ppm_path"`
	// PNGPath is the private PNG copy in the scratch directory, empty when it
	// could not be written. The caller removes it when it has no further use.
	PNGPath string `json:"png_path"`
	Base64  string `json:"base64"` // Base64 encoded PNG for report embedding
	// SHA256 is the SHA-256, lower-case hex, of the PNG (the bytes Base64
	// encodes), and PNGSize its length in bytes. A probe that does not keep
	// the image records the digest, so a report still says which image it saw.
	SHA256  string `json:"sha256"`
	PNGSize int    `json:"png_size"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
}

// writeFile writes the private PNG copy of a capture. Tests replace it with one
// that fails part way, as a full disk does.
var writeFile = os.WriteFile

// Option changes how Capture records the files it makes.
type Option func(*options)

type options struct {
	register func(paths ...string) error
	removed  func(paths ...string)
}

// WithRegister names a function Capture calls with the exact paths of the files
// it is about to ask for, before QEMU is asked to write the first of them, so
// that a caller can journal them: a worker killed while QEMU writes then still
// has them on record. A capture whose registration fails is not made.
func WithRegister(register func(paths ...string) error) Option {
	return func(o *options) { o.register = register }
}

// WithRemoved names a function Capture calls with the paths it has removed, or
// found already gone, so that the caller can drop them from its record. The PNG
// of a capture that succeeded is the caller's to remove and to report.
func WithRemoved(removed func(paths ...string)) Option {
	return func(o *options) { o.removed = removed }
}

// Capture invokes QMP screendump, converts the resulting PPM to PNG, and returns the artifact.
// ctx bounds the wait for QEMU: canceling it ends the capture at once, with
// nothing left in outputDir, instead of at the QMP command timeout.
func Capture(ctx context.Context, client *qmp.Client, vmid int, outputDir string, opts ...Option) (*Artifact, error) {
	var settings options
	for _, opt := range opts {
		opt(&settings)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("screendump of VM %d not taken: %w", vmid, err)
	}
	if outputDir == "" {
		outputDir = sysutil.DefaultScratchDir
	}
	if err := sysutil.EnsurePrivateDirectory(outputDir); err != nil {
		return nil, fmt.Errorf("failed to prepare private screendump directory: %w", err)
	}

	// Unique to this capture (two within one second, or two runs, never share a
	// name), and of a form recovery recognises as a diagnostic file of CertiStack's.
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("screendump of VM %d not taken: %w", vmid, err)
	}
	stem := fmt.Sprintf("certistack-failure-vm%d-%d-%s", vmid, time.Now().Unix(), hex.EncodeToString(nonce[:]))
	ppmPath := filepath.Join(outputDir, stem+".ppm")
	pngPath := filepath.Join(outputDir, stem+".png")
	if settings.register != nil {
		if err := settings.register(ppmPath, pngPath); err != nil {
			return nil, fmt.Errorf("screendump of VM %d not taken: its files could not be recorded for recovery: %w", vmid, err)
		}
	}

	slog.Info("capturing forensic screendump via QMP", "vmid", vmid, "ppm_path", ppmPath)
	// The raw frame is removed on every path, including a screendump command
	// that failed after QEMU had begun to write it.
	pngMade, pngRegistered := false, pngPath
	defer func() {
		// A PNG that was never made needs no removing: it is dropped from the
		// record with the frame.
		gone := []string{}
		if !pngMade {
			gone = append(gone, pngRegistered)
		}
		if err := os.Remove(ppmPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("could not remove a raw screendump frame; it stays recorded for teardown and recovery", "path", ppmPath, "error", err)
		} else {
			gone = append(gone, ppmPath)
		}
		if settings.removed != nil && len(gone) > 0 {
			settings.removed(gone...)
		}
	}()
	if err := client.ScreendumpContext(ctx, ppmPath); err != nil {
		return nil, fmt.Errorf("screendump failed for VM %d: %w", vmid, err)
	}

	ppmFile, err := os.Open(ppmPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open captured PPM %s: %w", ppmPath, err)
	}
	defer ppmFile.Close()

	var pngBuf bytes.Buffer
	width, height, err := ConvertPPMToPNG(ppmFile, &pngBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PPM to PNG: %w", err)
	}

	// Write PNG to disk
	if err := writeFile(pngPath, pngBuf.Bytes(), 0600); err != nil {
		slog.Warn("could not write PNG screenshot to disk", "path", pngPath, "error", err)
		// A partly written file is not an artifact, and nothing would remove
		// it: the caller tracks only the path it is given.
		_ = os.Remove(pngPath)
		pngPath = ""
	} else {
		pngMade = true
	}

	b64 := base64.StdEncoding.EncodeToString(pngBuf.Bytes())
	digest := sha256.Sum256(pngBuf.Bytes())

	slog.Info("forensic screenshot encoded successfully",
		"vmid", vmid, "width", width, "height", height, "png_path", pngPath)

	return &Artifact{
		PPMPath: ppmPath,
		PNGPath: pngPath,
		Base64:  b64,
		SHA256:  hex.EncodeToString(digest[:]),
		PNGSize: pngBuf.Len(),
		Width:   width,
		Height:  height,
	}, nil
}

// ConvertPPMToPNG parses a P6 binary PPM image and encodes it to PNG format.
const (
	// MaxPPMWidth defines the maximum allowable screendump width (4K resolution)
	MaxPPMWidth = 4096
	// MaxPPMHeight defines the maximum allowable screendump height
	MaxPPMHeight = 4096
	// MaxPPMPixels limits total pixel allocation to prevent memory exhaustion (16.7M pixels)
	MaxPPMPixels = 4096 * 4096
)

// ConvertPPMToPNG parses a P6 binary PPM image and encodes it to PNG format with bounds checking.
func ConvertPPMToPNG(r io.Reader, w io.Writer) (width int, height int, err error) {
	br := bufio.NewReader(r)

	magic, err := readToken(br)
	if err != nil {
		return 0, 0, fmt.Errorf("reading PPM magic: %w", err)
	}
	if magic != "P6" {
		return 0, 0, fmt.Errorf("unsupported PPM format: %s (only binary P6 supported)", magic)
	}

	widthStr, err := readToken(br)
	if err != nil {
		return 0, 0, err
	}
	width, err = strconv.Atoi(widthStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid width %q: %w", widthStr, err)
	}

	heightStr, err := readToken(br)
	if err != nil {
		return 0, 0, err
	}
	height, err = strconv.Atoi(heightStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid height %q: %w", heightStr, err)
	}

	if width <= 0 || width > MaxPPMWidth || height <= 0 || height > MaxPPMHeight {
		return 0, 0, fmt.Errorf("PPM dimensions out of safe range: %dx%d (max %dx%d)", width, height, MaxPPMWidth, MaxPPMHeight)
	}
	if width*height > MaxPPMPixels {
		return 0, 0, fmt.Errorf("PPM pixel count %d exceeds maximum safe allocation of %d", width*height, MaxPPMPixels)
	}

	maxvalStr, err := readToken(br)
	if err != nil {
		return 0, 0, err
	}
	maxval, err := strconv.Atoi(maxvalStr)
	if err != nil || maxval != 255 {
		return 0, 0, fmt.Errorf("unsupported maxval: %s (expected 255)", maxvalStr)
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rowBuf := make([]byte, width*3)

	for y := 0; y < height; y++ {
		if _, err := io.ReadFull(br, rowBuf); err != nil {
			return 0, 0, fmt.Errorf("reading row %d: %w", y, err)
		}
		for x := 0; x < width; x++ {
			offset := x * 3
			img.SetRGBA(x, y, color.RGBA{
				R: rowBuf[offset],
				G: rowBuf[offset+1],
				B: rowBuf[offset+2],
				A: 255,
			})
		}
	}

	if err := png.Encode(w, img); err != nil {
		return 0, 0, fmt.Errorf("encoding PNG: %w", err)
	}

	return width, height, nil
}

func readToken(r *bufio.Reader) (string, error) {
	var token []byte
	for {
		ch, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		if ch == '#' {
			// Skip comment line
			for {
				c, err := r.ReadByte()
				if err != nil {
					return "", err
				}
				if c == '\n' {
					break
				}
			}
			continue
		}

		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			if len(token) > 0 {
				return string(token), nil
			}
			continue
		}

		token = append(token, ch)
	}
}
