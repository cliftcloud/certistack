// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package screendump

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

func TestConvertPPMToPNG_Valid(t *testing.T) {
	// Create a minimal 2x2 P6 PPM image:
	// P6\n2 2\n255\n[12 bytes of RGB]
	var ppm bytes.Buffer
	ppm.WriteString("P6\n# Test comment\n2 2\n255\n")
	// 4 pixels: Red, Green, Blue, White
	ppm.Write([]byte{
		255, 0, 0, // Red
		0, 255, 0, // Green
		0, 0, 255, // Blue
		255, 255, 255, // White
	})

	var pngBuf bytes.Buffer
	w, h, err := ConvertPPMToPNG(&ppm, &pngBuf)
	if err != nil {
		t.Fatalf("expected PPM conversion to succeed, got %v", err)
	}

	if w != 2 || h != 2 {
		t.Errorf("expected 2x2 image, got %dx%d", w, h)
	}

	// Verify the output is valid PNG by decoding it
	img, err := png.Decode(&pngBuf)
	if err != nil {
		t.Fatalf("failed to decode generated PNG: %v", err)
	}

	bounds := img.Bounds()
	if bounds.Dx() != 2 || bounds.Dy() != 2 {
		t.Errorf("PNG bounds mismatch: %v", bounds)
	}
}

func TestConvertPPMToPNG_InvalidMagic(t *testing.T) {
	ppm := bytes.NewReader([]byte("P3\n2 2\n255\n0 0 0"))
	var pngBuf bytes.Buffer
	_, _, err := ConvertPPMToPNG(ppm, &pngBuf)
	if err == nil {
		t.Fatal("expected error on non-P6 format, got nil")
	}
}

func TestConvertPPMToPNG_ExceedsDimensions(t *testing.T) {
	ppm := bytes.NewReader([]byte("P6\n5000 5000\n255\n"))
	var pngBuf bytes.Buffer
	_, _, err := ConvertPPMToPNG(ppm, &pngBuf)
	if err == nil {
		t.Fatal("expected error on oversized dimensions, got nil")
	}
}

// Only 8-bit samples are converted: a 16-bit PPM (maxval 65535) or any other
// maxval would be read at the wrong width, so it is refused and nothing is
// written to the output.
func TestConvertPPMToPNG_RefusesAnyMaxvalButAnd255(t *testing.T) {
	for _, maxval := range []string{"0", "1", "15", "254", "256", "65535", "-1", "abc"} {
		ppm := bytes.NewReader([]byte("P6\n1 1\n" + maxval + "\n\x00\x00\x00"))
		var pngBuf bytes.Buffer
		_, _, err := ConvertPPMToPNG(ppm, &pngBuf)
		if err == nil || !strings.Contains(err.Error(), "maxval") {
			t.Errorf("maxval %q: error = %v, want a maxval refusal", maxval, err)
		}
		if pngBuf.Len() != 0 {
			t.Errorf("maxval %q: %d bytes were written to the output", maxval, pngBuf.Len())
		}
	}
}
