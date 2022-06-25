package main

import (
	"bytes"
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"github.com/xujiajun/nutsdb"
	"net/http"
	"strconv"
)

var bucket = "auth"

type KeyBuilder struct {
	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	Subdomain string `json:"subdomain"`
}

func (s KeyBuilder) Key() string {
	if s.ProxyType == "https" ||
		s.ProxyType == "http" {
		return fmt.Sprintf("http-s-%s-%d", s.Subdomain, s.RemotePort)
	} else {
		return fmt.Sprintf("%s-%s-%d", s.ProxyType, s.ProxyName, s.RemotePort)
	}
}

type SignBody struct {
	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	Subdomain string `json:"subdomain"`

	AuthKey string `json:"auth_key"`

	ValidTo string `json:"auth_valid_to"`
}

func (s SignBody) Sign() string {
	var preSign string
	if s.ProxyType == "http" ||
		s.ProxyType == "https" {
		preSign = fmt.Sprintf("__pt:http[s]__,__sb:%s__,__vt:%s__,__sk:%s__", s.Subdomain, s.ValidTo, s.AuthKey)
	} else {
		preSign = fmt.Sprintf("__pt:%s__,__rp:%d__,__vt:%s__,__sk:%s__", s.ProxyType, s.RemotePort, s.ValidTo, s.AuthKey)
	}
	return SignMD5(preSign)
}

type AddAuthRequest struct {
	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	ValidTo int64 `json:"auth_valid_to"`

	Memo string `json:"memo"`
}

type UpdateAuthRequest struct {
	Id string `json:"id"`

	ValidTo int64 `json:"auth_valid_to"`

	Memo string `json:"memo"`
}

type AuthDataEntity struct {
	Id string `json:"id"`

	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	ValidTo int64 `json:"auth_valid_to"`

	Memo string `json:"memo"`

	AuthKey string `json:"auth_key"`

	Sign string `json:"sign"`

	Disabled bool `json:"disabled"`
}

func SignMD5(text string) string {
	Log.Info(text)
	text = fmt.Sprintf("{%s,%s-%s}", text, Config.Salt, text)
	ctx := md5.New()
	ctx.Write([]byte(text))
	return hex.EncodeToString(ctx.Sum(nil))
}

func createSignKey() string {
	v4 := uuid.NewV4()
	return v4.String()
}

func AddAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Please send a request body.", 400)
		return
	}
	var aa AddAuthRequest
	err := json.NewDecoder(r.Body).Decode(&aa)
	if err != nil {
		fmt.Fprint(w, "Please send a valid request body.", 500)
		return
	}
	Log.Info("add", aa)
	kb := &KeyBuilder{
		ProxyName:  aa.ProxyName,
		ProxyType:  aa.ProxyType,
		RemotePort: aa.RemotePort,
		Subdomain:  aa.ProxyName,
	}
	key := kb.Key()
	signBody := &SignBody{
		ProxyType:  aa.ProxyType,
		RemotePort: aa.RemotePort,
		Subdomain:  aa.ProxyName,
		ValidTo:    strconv.FormatInt(aa.ValidTo, 10),
		AuthKey:    createSignKey(),
	}
	sign := signBody.Sign()
	ai := &AuthDataEntity{
		Id:         key,
		ProxyName:  aa.ProxyName,
		ProxyType:  aa.ProxyType,
		RemotePort: aa.RemotePort,
		ValidTo:    aa.ValidTo,
		Memo:       aa.Memo,
		AuthKey:    signBody.AuthKey,
		Sign:       sign,
	}
	val, err := json.Marshal(ai)
	if err != nil {
		Log.Error("Add auth failed.")
		http.Error(w, "server error[AddAuth-0].", 500)
		return
	}
	if err := Db.Update(
		func(tx *nutsdb.Tx) error {
			if err := tx.Put(bucket, []byte(key), val, 0); err != nil {
				return err
			}
			return nil
		}); err != nil {
		Log.Error(err)
		http.Error(w, "server error[AddAuth-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":0}`)
}

func ListAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	result := list.New()
	if err := Db.View(
		func(tx *nutsdb.Tx) error {
			entries, err := tx.GetAll(bucket)
			if err != nil {
				return err
			}

			for _, et := range entries {
				var ae AuthDataEntity
				err := json.Unmarshal(et.Value, &ae)
				if err != nil {
					return err
				}
				result.PushBack(ae)
			}
			return nil
		}); err != nil && err != nutsdb.ErrBucketEmpty {
		Log.Error(err)
		http.Error(w, "server error[ListAuth-1].", 500)
		return
	}
	resultJson := prepareListAuthServeHTTPResp(result)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, fmt.Sprintf(`{"code":0,"count":%d,"data":[%s]}`, result.Len(), resultJson))
}

func prepareListAuthServeHTTPResp(list *list.List) string {
	var buffer bytes.Buffer
	for it := list.Front(); nil != it; {
		j, err := json.Marshal(it.Value)
		if nil != err {
			Log.Error("server error[prepareListAuthResp-1].")
			return ""
		}
		buffer.Write(j)
		it = it.Next()
		if nil == it {
			break
		}
		buffer.Write([]byte(","))
	}
	return buffer.String()
}

func GetAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var ae AuthDataEntity
	err := Db.View(func(tx *nutsdb.Tx) error {
		e, err := tx.Get(bucket, []byte(params["id"]))
		if nil != err {
			return err
		}
		err2 := json.Unmarshal(e.Value, &ae)
		if nil != err2 {
			return err2
		}
		return nil
	})
	if nil != err {
		Log.Error(err)
		http.Error(w, "server error[GetAuth-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	aeJson, err := json.Marshal(ae)
	if nil != err {
		Log.Error(err)
		http.Error(w, "server error[GetAuth-2].", 500)
		return
	}
	fmt.Fprint(w, string(aeJson))
}

func DisableAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	Log.Info("disable", params["id"])
	if err := Db.Update(func(tx *nutsdb.Tx) error {
		var ae AuthDataEntity
		e, err := tx.Get(bucket, []byte(params["id"]))
		if nil != err {
			return err
		}
		err2 := json.Unmarshal(e.Value, &ae)
		if nil != err2 {
			return err2
		}

		ae.Disabled = true
		val, err := json.Marshal(ae)
		if nil != err {
			return err
		}
		if err := tx.Put(bucket, []byte(params["id"]), val, 0); err != nil {
			return err
		}
		return nil
	}); err != nil {
		Log.Error(err)
		http.Error(w, "server error[DisableAuth-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":0}`)

}

func EnableAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	Log.Info("enable", params["id"])
	if err := Db.Update(func(tx *nutsdb.Tx) error {
		var ae AuthDataEntity
		e, err := tx.Get(bucket, []byte(params["id"]))
		if nil != err {
			return err
		}
		err2 := json.Unmarshal(e.Value, &ae)
		if nil != err2 {
			return err2
		}

		ae.Disabled = false
		val, err := json.Marshal(ae)
		if nil != err {
			return err
		}
		if err := tx.Put(bucket, []byte(params["id"]), val, 0); err != nil {
			return err
		}
		return nil
	}); err != nil {
		Log.Error(err)
		http.Error(w, "server error[EnableAuth-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":0}`)

}

func UpdateAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Please send a request body.", 400)
		return
	}
	var ua UpdateAuthRequest
	err := json.NewDecoder(r.Body).Decode(&ua)
	if err != nil {
		fmt.Fprint(w, "Please send a valid request body.", 500)
		return
	}
	Log.Info("update", ua)
	if err := Db.Update(
		func(tx *nutsdb.Tx) error {

			var ae AuthDataEntity
			e, err := tx.Get(bucket, []byte(ua.Id))
			if nil != err {
				return err
			}
			err2 := json.Unmarshal(e.Value, &ae)
			if nil != err2 {
				return err2
			}

			ae.Memo = ua.Memo
			ae.ValidTo = ua.ValidTo
			signBody := &SignBody{
				ProxyType:  ae.ProxyType,
				RemotePort: ae.RemotePort,
				Subdomain:  ae.ProxyName,
				AuthKey:    ae.AuthKey,
				ValidTo:    strconv.FormatInt(ae.ValidTo, 10),
			}
			ae.Sign = signBody.Sign()

			val, err := json.Marshal(ae)
			if nil != err {
				return err
			}
			if err := tx.Put(bucket, []byte(ua.Id), val, 0); err != nil {
				return err
			}
			return nil
		}); err != nil {
		Log.Error(err)
		http.Error(w, "server error[UpdateAuth-1].", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":0}`)

}

func DeleteAuthServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	Log.Info("delete", params["id"])
	err := Db.Update(func(tx *nutsdb.Tx) error {
		err := tx.Delete(bucket, []byte(params["id"]))
		if nil != err {
			return err
		}
		return nil
	})
	if nil != err {
		Log.Error(err)
		http.Error(w, "server error[DeleteAuth-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":0}`)
}

func GetAuthConfigServerHTTP(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var ae AuthDataEntity
	err := Db.View(func(tx *nutsdb.Tx) error {
		e, err := tx.Get(bucket, []byte(params["id"]))
		if nil != err {
			return err
		}
		err2 := json.Unmarshal(e.Value, &ae)
		if nil != err2 {
			return err2
		}
		return nil
	})
	if nil != err {
		Log.Error(err)
		http.Error(w, "server error[GetAuthConfig-1].", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	var bodyStr string
	if ae.ProxyType == "http" ||
		ae.ProxyType == "https" {
		bodyStr = fmt.Sprintf(`
		<div>[%s-%s]</div>
		<div>type=%s</div>
		<div>subdomain=%s</div>
		<div>meta_auth_valid_to=%s</div>
		<div>meta_auth_key=%s</div>
		<div>use_gzip=true</div>
		<div>#local_ip=</div>
		<div>#local_port=</div>
		<div>#pool_count=20</div>
		<div>#http_user=admin</div>
		<div>#http_pwd=admin</div>`, ae.ProxyType, ae.ProxyName, ae.ProxyType, ae.ProxyName, strconv.FormatInt(ae.ValidTo, 10), ae.AuthKey)

	} else if ae.ProxyType == "xtcp" ||
		ae.ProxyType == "stcp" {
		fmt.Fprint(w, fmt.Sprintf(`
		<div>[%s]</div>
		<div>type=%s</div>
		<div>sk=changeme!</div>
		<div># connect this address to visitor stcp server</div>
		<div>bind_addr=127.0.0.1</div>
		<div>bind_port=0</div>
		<div>meta_auth_valid_to=%s</div>
		<div>meta_auth_key=%s</div>
		<div># frpc role visitor -> frps -> frpc role server</div>
		<div>#role=visitor</div>
		<div># the server name you want to visitor</div>
		<div>#server_name=changeme!</div>
		<div>#use_encryption=false</div>
		<div>#use_compression=false</div>
		`, ae.ProxyName, ae.ProxyType, strconv.FormatInt(ae.ValidTo, 10), ae.AuthKey))
	} else {
		fmt.Fprint(w, fmt.Sprintf(`
		<div>[%s]</div>
		<div>type=%s</div>
		<div>remote_port=%d</div>
		<div>meta_auth_valid_to=%s</div>
		<div>meta_auth_key=%s</div>
		<div>#local_ip=</div>
		<div>#local_port=</div>
		<div>#use_compression=false</div>
		<div>#use_compression = true</div>
		`, ae.ProxyName, ae.ProxyType, ae.RemotePort, strconv.FormatInt(ae.ValidTo, 10), ae.AuthKey))
	}

	fmt.Fprint(w, fmt.Sprintf(`<html>
		<head>
		<title>授权信息</title>
		<style>
			div {
				padding-left:20px;
			}
		</style>
		</head>
		<body>
		%s
		</body>
		</html>`, bodyStr))

}
