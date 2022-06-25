package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var embedFS embed.FS

func getStaticFS(path string) http.FileSystem {
	if path != "" {
		return http.Dir(path)
	} else {
		staticFS, err := fs.Sub(embedFS, "static")
		if err != nil {
			panic(err)
		}
		return http.FS(staticFS)
	}
}
