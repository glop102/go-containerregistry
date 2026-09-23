// Copyright 2026 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mutate_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// entry is one tar member of a synthetic layer.  Member order matters for
// some of the cases below, so layers are described as ordered slices.
type entry struct {
	name string
	// one of: "dir", "file", "symlink", "hardlink", "whiteout", "opaque"
	kind string
	// file body, symlink target or hardlink target
	arg string
}

func dir(name string) entry              { return entry{name, "dir", ""} }
func file(name, body string) entry       { return entry{name, "file", body} }
func symlink(name, target string) entry  { return entry{name, "symlink", target} }
func hardlink(name, target string) entry { return entry{name, "hardlink", target} }
func whiteout(name string) entry         { return entry{name, "whiteout", ""} }
func opaque(dirName string) entry        { return entry{dirName, "opaque", ""} }

func layerOf(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		var h *tar.Header
		switch e.kind {
		case "dir":
			h = &tar.Header{Name: e.name + "/", Typeflag: tar.TypeDir, Mode: 0o755}
		case "file":
			h = &tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.arg))}
		case "symlink":
			h = &tar.Header{Name: e.name, Typeflag: tar.TypeSymlink, Linkname: e.arg, Mode: 0o777}
		case "hardlink":
			h = &tar.Header{Name: e.name, Typeflag: tar.TypeLink, Linkname: e.arg, Mode: 0o644}
		case "whiteout":
			d, b := splitDir(e.name)
			h = &tar.Header{Name: d + ".wh." + b, Typeflag: tar.TypeReg, Mode: 0o644}
		case "opaque":
			h = &tar.Header{Name: e.name + "/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644}
		default:
			t.Fatalf("unknown entry kind %q", e.kind)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.kind == "file" {
			if _, err := tw.Write([]byte(e.arg)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func splitDir(name string) (string, string) {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[:i+1], name[i+1:]
		}
	}
	return "", name
}

// extractTree flattens img and returns a description of every entry in the
// exported tar, resolving hardlinks to the content they point at:
//
//	"dir"            directory
//	"file:<body>"    regular file (or a hardlink to one)
//	"symlink:<tgt>"  symlink
func extractTree(t *testing.T, img v1.Image) map[string]string {
	t.Helper()
	got := map[string]string{}
	tr := tar.NewReader(mutate.Extract(img))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading extracted tar: %v", err)
		}
		name := h.Name
		if len(name) > 1 && name[len(name)-1] == '/' {
			name = name[:len(name)-1]
		}
		switch h.Typeflag {
		case tar.TypeDir:
			got[name] = "dir"
		case tar.TypeReg:
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			got[name] = "file:" + string(body)
		case tar.TypeSymlink:
			got[name] = "symlink:" + h.Linkname
		case tar.TypeLink:
			target, ok := got[h.Linkname]
			if !ok {
				t.Errorf("hardlink %q -> %q points at an entry that is not in the export (or precedes it); a tar extractor cannot restore this", name, h.Linkname)
				got[name] = "dangling-hardlink:" + h.Linkname
				continue
			}
			got[name] = target
		default:
			got[name] = "other"
		}
	}
	return got
}

// TestExtractLayerSemantics pins down the image-spec rules for applying
// layers (https://github.com/opencontainers/image-spec/blob/main/layer.md):
//
//   - whiteouts only hide entries from *lower* layers, never siblings in the
//     same layer, regardless of member order;
//   - an entry replaces whatever a lower layer had at that path, and if a
//     directory was replaced by a non-directory everything beneath it stays
//     gone even when a higher layer turns the path into a directory again;
//   - a hardlink keeps its layer's content even when the name it links to is
//     hidden or replaced by an upper layer;
//   - AUFS bookkeeping entries (.wh..wh.plnk/, .wh..wh.orph/, .wh..wh.aufs)
//     never reach the export, though hardlinks into .wh..wh.plnk/ still get
//     their content;
//   - a symlink (or any non-directory) in a lower layer is replaced outright
//     when an upper layer turns that path into a directory, whether with an
//     explicit directory entry or merely by having entries beneath it;
//     a lower directory merges with such an implied directory instead.
func TestExtractLayerSemantics(t *testing.T) {
	tests := []struct {
		name   string
		layers [][]entry
		want   map[string]string
	}{
		{
			name: "whiteout dir then readd in later layer",
			layers: [][]entry{
				{dir("d"), file("d/old", "old")},
				{whiteout("d")},
				{dir("d"), file("d/new", "new")},
			},
			want: map[string]string{"d": "dir", "d/new": "file:new"},
		},
		{
			name: "dir replaced by file then by dir again",
			layers: [][]entry{
				{dir("d"), file("d/old", "old")},
				{file("d", "file")},
				{dir("d"), file("d/new", "new")},
			},
			want: map[string]string{"d": "dir", "d/new": "file:new"},
		},
		{
			name: "dir replaced by symlink then by dir again",
			layers: [][]entry{
				{dir("d"), file("d/old", "old")},
				{symlink("d", "elsewhere")},
				{dir("d"), file("d/new", "new")},
			},
			want: map[string]string{"d": "dir", "d/new": "file:new"},
		},
		{
			name: "same layer: whiteout listed before the file it names",
			layers: [][]entry{
				{dir("d"), file("d/keep", "keep"), file("d/z", "old")},
				{dir("d"), whiteout("d/z"), file("d/z", "new")},
			},
			want: map[string]string{"d": "dir", "d/keep": "file:keep", "d/z": "file:new"},
		},
		{
			name: "same layer: whiteout listed after the file it names",
			layers: [][]entry{
				{dir("d"), file("d/keep", "keep"), file("d/z", "old")},
				{dir("d"), file("d/z", "new"), whiteout("d/z")},
			},
			want: map[string]string{"d": "dir", "d/keep": "file:keep", "d/z": "file:new"},
		},
		{
			name: "same layer: whiteout dir and recreate it",
			layers: [][]entry{
				{dir("d"), file("d/old", "old"), file("d/keep", "keep")},
				{whiteout("d"), dir("d"), file("d/new", "new")},
			},
			want: map[string]string{"d": "dir", "d/new": "file:new"},
		},
		{
			name: "same layer: whiteout file and recreate it as a dir",
			layers: [][]entry{
				{file("x", "file")},
				{whiteout("x"), dir("x"), file("x/y", "y")},
			},
			want: map[string]string{"x": "dir", "x/y": "file:y"},
		},
		{
			name: "same layer: opaque dir and re-added child",
			layers: [][]entry{
				{dir("d"), file("d/a", "old-a"), file("d/b", "old-b")},
				{dir("d"), opaque("d"), file("d/a", "new-a")},
			},
			want: map[string]string{"d": "dir", "d/a": "file:new-a"},
		},
		{
			name: "hardlink whose target is whited out above",
			layers: [][]entry{
				{file("f1", "shared"), hardlink("f2", "f1")},
				{whiteout("f1")},
			},
			want: map[string]string{"f2": "file:shared"},
		},
		{
			name: "hardlink whose target is overwritten above",
			layers: [][]entry{
				{file("f1", "old"), hardlink("f2", "f1")},
				{file("f1", "new")},
			},
			want: map[string]string{"f1": "file:new", "f2": "file:old"},
		},
		{
			name: "hardlink whose target is inside an opaque dir",
			layers: [][]entry{
				{dir("d"), file("d/f1", "shared"), hardlink("d/f2", "d/f1")},
				{dir("d"), opaque("d"), dir("e"), hardlink("e/f3", "d/f1")},
			},
			// e/f3 links to d/f1 from its own layer's point of view, but
			// that layer does not carry d/f1: the link is unresolvable and
			// is dropped rather than exported dangling.
			want: map[string]string{"d": "dir", "e": "dir"},
		},
		{
			name: "hardlink pair both surviving",
			layers: [][]entry{
				{file("f1", "shared"), hardlink("f2", "f1")},
			},
			want: map[string]string{"f1": "file:shared", "f2": "file:shared"},
		},
		{
			name: "hardlink with ./ prefixed target",
			layers: [][]entry{
				{file("./f1", "shared"), hardlink("./f2", "./f1")},
			},
			want: map[string]string{"f1": "file:shared", "f2": "file:shared"},
		},
		{
			name: "aufs metadata entries are never exported",
			layers: [][]entry{
				{
					dir(".wh..wh.plnk"), file(".wh..wh.plnk/1", "lower-plnk"),
					dir(".wh..wh.orph"), file(".wh..wh.orph/gone", "lower-orph"),
					file(".wh..wh.aufs", ""),
					dir("d"), file("d/lower", "lower"),
				},
				{
					dir(".wh..wh.plnk"), file(".wh..wh.plnk/2", "upper-plnk"),
					dir(".wh..wh.orph"), file(".wh..wh.orph/gone", "upper-orph"),
					file(".wh..wh.aufs", ""),
					dir("d"), file("d/upper", "upper"),
				},
			},
			want: map[string]string{"d": "dir", "d/lower": "file:lower", "d/upper": "file:upper"},
		},
		{
			name: "aufs hardlink placeholder resolves to its content",
			layers: [][]entry{
				{
					dir(".wh..wh.plnk"), file(".wh..wh.plnk/42.1", "shared"),
					dir("bin"), hardlink("bin/a", ".wh..wh.plnk/42.1"), hardlink("bin/b", ".wh..wh.plnk/42.1"),
				},
			},
			want: map[string]string{"bin": "dir", "bin/a": "file:shared", "bin/b": "file:shared"},
		},
		{
			name: "symlink to a file replaced by a dir of the same name above",
			layers: [][]entry{
				{dir("real"), file("real/target", "target"), symlink("link", "real/target")},
				{dir("link"), file("link/child", "child")},
			},
			want: map[string]string{
				"real": "dir", "real/target": "file:target",
				"link": "dir", "link/child": "file:child",
			},
		},
		{
			name: "symlink to a file replaced by an implicit dir of the same name above",
			layers: [][]entry{
				// no dir entries: "real" and "link" exist only because file
				// paths beneath them do, which is common in ad-hoc layers.
				{file("real/target", "target"), symlink("link", "real/target")},
				{file("link/child", "child")},
			},
			// The upper layer's link/child implies link is a directory there,
			// so the lower symlink at link must not show through: extracting
			// the result would otherwise write child through the symlink into
			// real/, or fail.
			want: map[string]string{
				"real/target": "file:target",
				"link/child":  "file:child",
			},
		},
		{
			name: "explicit dir below merges with an implicit dir above",
			layers: [][]entry{
				{dir("d"), file("d/old", "old")},
				{file("d/new", "new")},
			},
			// An implied directory only replaces non-directories; the lower
			// layer's explicit d/ entry (and its metadata) is kept.
			want: map[string]string{"d": "dir", "d/old": "file:old", "d/new": "file:new"},
		},
		{
			name: "dir replaced by symlink then by an implicit dir again",
			layers: [][]entry{
				{dir("d"), file("d/old", "old")},
				{symlink("d", "elsewhere")},
				{file("d/new", "new")},
			},
			// The middle layer's symlink wiped the bottom directory, so d/old
			// must not resurface under the top layer's implied d/.
			want: map[string]string{"d/new": "file:new"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layers := make([]v1.Layer, 0, len(tt.layers))
			for _, l := range tt.layers {
				layers = append(layers, layerOf(t, l...))
			}
			img, err := mutate.AppendLayers(empty.Image, layers...)
			if err != nil {
				t.Fatal(err)
			}
			got := extractTree(t, img)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("extracted tree mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
