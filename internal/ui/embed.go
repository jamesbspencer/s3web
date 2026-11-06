package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var embeddedAssets embed.FS

// FileSystem returns an http.FileSystem serving the embedded static Web UI assets.
func FileSystem() http.FileSystem {
	sub, err := fs.Sub(embeddedAssets, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

