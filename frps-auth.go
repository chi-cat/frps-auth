package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"github.com/xujiajun/nutsdb"
	"gopkg.in/ini.v1"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	httpServerReadTimeout  = 10 * time.Second
	httpServerWriteTimeout = 10 * time.Second
)

func createLog() (*os.File, *logging.Logger) {
	var logFilename string = "frps-auth.log"
	logFile, err := os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("log file is unwritable.")
		os.Exit(-1)
	}
	l := logging.MustGetLogger("frps-auth")
	backend1 := logging.NewLogBackend(logFile, "", 0)
	backend2 := logging.NewLogBackend(os.Stderr, "", 0)
	backend1Formatter := logging.NewBackendFormatter(backend1, format)
	backend2Formatter := logging.NewBackendFormatter(backend2, format)
	backend1Leveled := logging.AddModuleLevel(backend1Formatter)
	backend1Leveled.SetLevel(logging.INFO, "")
	logging.SetBackend(backend1Leveled, backend2Formatter)
	return logFile, l
}

var logFile, Log = createLog()
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} > %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func createDB() *nutsdb.DB {
	opt := nutsdb.DefaultOptions
	opt.Dir = "frps-auth-db"
	db, err := nutsdb.Open(opt)
	if err != nil {
		Log.Error("open db failed.")
	}
	return db
}

var Db = createDB()

type AuthConfig struct {
	Address  string `ini:"address"`
	Port     string `ini:"port"`
	Username string `ini:"username"`
	Password string `ini:"password"`
	Salt     string `ini:"salt"`
}

var Config AuthConfig = AuthConfig{
	Address:  "127.0.0.1",
	Port:     "4000",
	Username: "admin",
	Password: "admin",
	Salt:     "admin",
}

func init() {
	iniFile, err := ini.Load("frps-auth.ini")
	if err != nil {
		Log.Error(err)
		return
	}
	iniFile.BlockMode = false
	err = iniFile.MapTo(&Config)
	if err != nil {
		Log.Error(err)
		os.Exit(-1)
	}

}

type applyPortRequest struct {
	Version string `json:"version"`

	OpType string `json:"op"`

	Content applyPortContent `json:"content"`
}

type applyPortContent struct {
	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	Subdomain string `json:"subdomain"`

	Metas applyPortContentAuthMeta `json:"metas,omitempty"`
}

type applyPortContentAuthMeta struct {
	ValidTo string `json:"valid_to"`
}

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Please send a request body.", 400)
		return
	}
	var apr applyPortRequest
	err := json.NewDecoder(r.Body).Decode(&apr)
	if err != nil {
		http.Error(w, "Please send a valid request body.", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if apr.OpType != "NewProxy" {
		fmt.Fprint(w, `{
			"reject": false,
			"unchange": true
		}`)
	} else {
		kb := &KeyBuilder{
			ProxyName:  apr.Content.ProxyName,
			ProxyType:  apr.Content.ProxyType,
			RemotePort: apr.Content.RemotePort,
			Subdomain:  apr.Content.Subdomain,
		}
		key := kb.Key()
		signBody := &SignBody{
			ProxyType:  apr.Content.ProxyType,
			RemotePort: apr.Content.RemotePort,
			Subdomain:  apr.Content.Subdomain,
			ValidTo:    apr.Content.Metas.ValidTo,
		}
		sign := signBody.Sign()
		err := Db.View(func(tx *nutsdb.Tx) error {
			var ae AuthDataEntity
			e, err := tx.Get(bucket, []byte(key))
			if nil != err {
				return err
			}
			err2 := json.Unmarshal(e.Value, &ae)
			if nil != err2 {
				return err2
			}
			if ae.Sign != sign {
				return errors.New(sign)
			}
			if (time.Now().UnixNano() / 1e6) > ae.ValidTo {
				return errors.New(time.Now().Format("yyyy-MM-dd"))
			}
			return nil
		})
		if nil != err {
			fmt.Fprint(w, fmt.Sprintf(`{
			 "reject": true,
			 "reject_reason": "invalid[%s]"
			}`, sign))
			return
		}
		fmt.Fprint(w, `{
			"reject": false,
			"unchange": true
		}`)
	}
}

func main() {
	Log.Info("start frps-auth.")
	router := mux.NewRouter()
	router.Use(NewHttpAuthMiddleware(Config.Username, Config.Password, "/auth").Middleware)
	router.HandleFunc("/auth", ServeHTTP).Methods("POST")
	router.HandleFunc("/add-auth", AddAuthServeHTTP).Methods("POST")
	router.HandleFunc("/update-auth", UpdateAuthServeHTTP).Methods("POST")
	router.HandleFunc("/delete-auth/{id}", DeleteAuthServeHTTP).Methods("POST")
	router.HandleFunc("/list-auth", ListAuthServeHTTP).Methods("POST")
	router.HandleFunc("/get-auth/{id}", GetAuthServeHTTP).Methods("GET")
	router.HandleFunc("/get-auth-config/{id}", GetAuthConfigServerHTTP).Methods("GET")
	router.PathPrefix("/auth-statistics/").Handler(MakeHttpGzipHandler(http.StripPrefix("/auth-statistics/", http.FileServer(http.Dir("static/"))))).Methods("GET")
	addr := Config.Address
	port := Config.Port

	address := fmt.Sprintf("%s:%s", addr, port)
	Log.Info(fmt.Sprintf("bind %s", address))
	server := &http.Server{
		Addr:         address,
		Handler:      router,
		ReadTimeout:  httpServerReadTimeout,
		WriteTimeout: httpServerWriteTimeout,
	}
	if address == "" {
		address = ":http"
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		os.Exit(-1)
	}
	defer Db.Close()
	defer logFile.Close()
	server.Serve(ln)
}
