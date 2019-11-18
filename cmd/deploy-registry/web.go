package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
)

func (tr *tracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		var keys []string
		_ = tr.db.View(func(tx *bolt.Tx) error {
			keys = fetchTxBucketKeys(tx, bktConfigs)
			return nil
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = indexPageTemplate.Execute(w, keys)
		return
	}
	switch r.Method {
	default:
		w.Header().Set("Allow", "GET, POST, PATCH")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	case http.MethodPost:
		tr.handleForm(w, r)
	case http.MethodPatch:
		tr.handlePatch(w, r)
	case http.MethodGet:
		tr.handleGet(w, r)
	}
}

func (tr *tracker) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(r.URL.Path)
	if name == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var cfg *Configuration
	type version struct {
		Time, Version string
		Selected      bool
	}
	page := struct {
		Name   string
		Hash   string
		Mtime  time.Time
		Layers []struct {
			Name     string
			Versions []version
		}
	}{Name: name}
	err := tr.db.View(func(tx *bolt.Tx) error {
		var err error
		if cfg, err = getTxConfiguration(tx, name); err != nil {
			return err
		}
		page.Mtime = cfg.Mtime
		page.Hash = cfg.Hash
		for _, layer := range cfg.Layers {
			vs := fetchTxBucketKeys(tx, bktComponents, layer.Name, bktByTime)
			versions := make([]version, len(vs))
			for i, v := range vs {
				ss := strings.SplitN(v, "#", 2) // values are encoded as "date#version"
				if len(ss) != 2 {
					return fmt.Errorf("malformed value for component %q: %q", layer, v)
				}
				versions[i] = version{Time: ss[0], Version: ss[1], Selected: ss[1] == layer.Version}
			}
			page.Layers = append(page.Layers, struct {
				Name     string
				Versions []version
			}{
				Name:     layer.Name,
				Versions: versions,
			})
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, layer := range page.Layers {
		sort.Slice(layer.Versions, func(i, j int) bool {
			return layer.Versions[i].Time > layer.Versions[j].Time
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = formPageTemplate.Execute(w, page)
}

func (tr *tracker) handleForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(r.URL.Path)
	if name == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	m := make(map[string]string, len(r.PostForm))
	var cfgHash string
	for k := range r.PostForm {
		if k == "cfg:hash" {
			cfgHash = r.PostForm.Get(k)
			continue
		}
		m[k] = r.PostForm.Get(k)
	}
	if cfgHash == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := tr.patchConfiguration(name, cfgHash, m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch user := r.Header.Get("X-Forwarded-User"); user {
	case "":
		log.Printf("updated %q with the following values: %+v", name, r.PostForm)
	default:
		log.Printf("%q updated %q with the following values: %+v", user, name, r.PostForm)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = redirectPageTemplate.Execute(w, r.URL.Path)
}

func (tr *tracker) handlePatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(r.URL.Path)
	if name == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Expecting application/json payload", http.StatusUnsupportedMediaType)
		return
	}
	m := make(map[string]string)
	rd := http.MaxBytesReader(w, r.Body, 1<<20)
	defer rd.Close()
	if err := json.NewDecoder(rd).Decode(&m); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := tr.patchConfiguration(name, "", m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch user := r.Header.Get("X-Forwarded-User"); user {
	case "":
		log.Printf("updated %q with the following values: %+v", name, m)
	default:
		log.Printf("%q updated %q with the following values: %+v", user, name, m)
	}
	w.WriteHeader(http.StatusNoContent)
}

// patchConfiguration updates configuration with given name, setting its
// existing layers to versions specified by compToVersion mapping, maps
// component name to its version.
//
// cfgHash is an optional hash of configuration; if non-empty, it will be
// checked for match with actual configuration hash before updating it. Update
// will be aborted on hash mismatch.
func (tr *tracker) patchConfiguration(name, cfgHash string, compToVersion map[string]string) error {
	if len(compToVersion) == 0 {
		return errors.New("nothing to update")
	}
	if name == "" {
		return errors.New("empty configuration name")
	}
	fn := func(tx *bolt.Tx) error {
		cfg, err := getTxConfiguration(tx, name)
		if err != nil {
			return err
		}
		if cfgHash != "" && cfgHash != cfg.Hash {
			return errors.New("configuration hash mismatch, please refresh state")
		}
		components := make([]*ComponentVersion, 0, len(compToVersion))
	inputLoop:
		for comp, version := range compToVersion {
			// Don't update layers that are already at the correct version.
			// This allows patch to be called with the full mapping set, i.e.
			// when input is collected from the web form, while avoiding
			// unnecessary cfg.replaceLayer calls for the same version that's
			// already applied.
			for _, layer := range cfg.Layers {
				if layer.Name == comp && layer.Version == version {
					continue inputLoop
				}
			}
			cv, err := getTxComponentVersion(tx, comp, version)
			if err != nil {
				return err
			}
			components = append(components, cv)
		}
		if len(components) == 0 {
			return nil
		}
		for _, cv := range components {
			if err := cfg.replaceLayer(cv); err != nil {
				return err
			}
		}
		return cfg.save(tx)
	}
	return multiUpdate(tr.db, fn)
}

var formPageTemplate = template.Must(template.New("form").Parse(`<!doctype html>
<head><meta charset="utf-8"><title>Configuration {{.Name}}</title><style>
    select {width:100%}
</style></head>
<form method="post">Configuration <strong>{{.Name}}</strong>,
modified at <time>{{.Mtime.Format "2006-01-02T15:04:05Z07:00"}}</time>
<table>{{range .Layers}}
<tr><td>{{.Name}}</td><td><select name="{{.Name}}">{{range .Versions}}
<option value="{{.Version}}"{{if .Selected}} selected{{end}}>{{.Version}} — {{.Time}}</option>
{{end}}</select></td></tr>
{{end}}</table>
<input type="hidden" value="{{.Hash}}" name="cfg:hash">
<!-- input name above chosen to have ":" because it's a forbidden symbol for
component name, so this avoids conflict with any real component name -->
<input type="submit" value="update configuration">
</form>
`))

var indexPageTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<head><meta charset="utf-8"><title>Known configurations</title></head>
<p>Known configurations:</p><ul>
{{range .}}<li><a href="{{.}}">{{.}}</a></li>{{end}}</ul>
`))

var redirectPageTemplate = template.Must(template.New("redirect").Parse(`<!doctype html>
<head><meta charset="utf-8"><meta http-equiv="refresh" content="2;url={{.}}"></head>
<pre>Update applied

See <a href="{{.}}">updated configuration</a>.
`))
