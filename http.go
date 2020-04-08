// Copyright 2017 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HttpAuthWrapper struct {
	h      http.Handler
	user   string
	passwd string
}

func NewHttpBasicAuthWrapper(h http.Handler, user, passwd string) http.Handler {
	return &HttpAuthWrapper{
		h:      h,
		user:   user,
		passwd: passwd,
	}
}

func (aw *HttpAuthWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, passwd, hasAuth := r.BasicAuth()
	if (aw.user == "" && aw.passwd == "") || (hasAuth && user == aw.user && passwd == aw.passwd) {
		aw.h.ServeHTTP(w, r)
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}

type HttpAuthMiddleware struct {
	user   string
	passwd string
	skip   string
}

func NewHttpAuthMiddleware(user, passwd, skip string) *HttpAuthMiddleware {
	return &HttpAuthMiddleware{
		user:   user,
		passwd: passwd,
		skip:   skip,
	}
}

func (authMid *HttpAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Log.Info(r.RequestURI)
		reqUser, reqPasswd, hasAuth := r.BasicAuth()
		if (authMid.user == "" && authMid.passwd == "") ||
			(hasAuth && reqUser == authMid.user && reqPasswd == authMid.passwd) ||
			r.URL.Path == authMid.skip {
			next.ServeHTTP(w, r)
		} else {
			Log.Warning(fmt.Sprintf("%s %s At %s failed.", reqUser, r.RequestURI, time.Now()))
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	})
}

func HttpBasicAuth(h http.HandlerFunc, user, passwd string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqUser, reqPasswd, hasAuth := r.BasicAuth()
		if (user == "" && passwd == "") ||
			(hasAuth && reqUser == user && reqPasswd == passwd) {
			h.ServeHTTP(w, r)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}

type HttpGzipWrapper struct {
	h http.Handler
}

func (gw *HttpGzipWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gw.h.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
	gw.h.ServeHTTP(gzr, r)
}

func MakeHttpGzipHandler(h http.Handler) http.Handler {
	return &HttpGzipWrapper{
		h: h,
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
