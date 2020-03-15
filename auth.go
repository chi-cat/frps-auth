package main

import (
	"bytes"
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/xujiajun/nutsdb"
	"net/http"
	"strconv"
)

var bucket = "auth"

type SignBody struct {
	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	Subdomain string `json:"subdomain"`

	ValidTo string `json:"valid_to"`
}

func (s SignBody) Sign() string {
	var preSign string
	if s.ProxyType == "http" ||
		s.ProxyType == "https" {
		preSign = fmt.Sprintf("__pt:http[s]__,__sb:%s__,__vt:%s__", s.Subdomain, s.ValidTo)
	} else {
		preSign = fmt.Sprintf("__pt:%s__,__rp:%d__,__vt:%s__", s.ProxyType, s.RemotePort, s.ValidTo)
	}
	return SignMD5(preSign)
}

type AddAuthRequest struct {
	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	ValidTo int64 `json:"valid_to"`

	Memo string `json:"memo"`
}

type UpdateAuthRequest struct {
	Id string `json:"id"`

	ValidTo int64 `json:"valid_to"`

	Memo string `json:"memo"`
}

type AuthDataEntity struct {
	Id string `json:"id"`

	ProxyName string `json:"proxy_name"`

	ProxyType string `json:"proxy_type"`

	RemotePort uint16 `json:"remote_port"`

	ValidTo int64 `json:"valid_to"`

	Memo string `json:"memo"`

	Sign string `json:"sign"`
}

func SignMD5(text string) string {
	Log.Info(text)
	fmt.Sprintf("{%s,%s-%s}", text, Config.Salt, text)
	ctx := md5.New()
	ctx.Write([]byte(text))
	return hex.EncodeToString(ctx.Sum(nil))
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
	key := fmt.Sprintf("%s-%s-%d", aa.ProxyType, aa.ProxyName, aa.RemotePort)
	signBody := &SignBody{
		ProxyType:  aa.ProxyType,
		RemotePort: aa.RemotePort,
		Subdomain:  aa.ProxyName,
		ValidTo:    strconv.FormatInt(aa.ValidTo, 10),
	}
	sign := signBody.Sign()
	ai := &AuthDataEntity{
		Id:         key,
		ProxyName:  aa.ProxyName,
		ProxyType:  aa.ProxyType,
		RemotePort: aa.RemotePort,
		ValidTo:    aa.ValidTo,
		Memo:       aa.Memo,
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
	Log.Info("add", ua)
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
	if ae.ProxyType == "http" ||
		ae.ProxyType == "https" {

		bodyStr := fmt.Sprintf(`
		<div>[%s-%s]</div>
		<div>type=%s</div>
		<div>subdomain=%s</div>
		<div>meta_valid_to=%s</div>
		<div>meta_sign=%s</div>
		<div>use_gzip=true</div>
		<div>#local_ip=</div>
		<div>#local_port=</div>
		<div>#pool_count=20</div>
		<div>#http_user=admin</div>
		<div>#http_pwd=admin</div>
		`, ae.ProxyType, ae.ProxyName, ae.ProxyType, ae.ProxyName, strconv.FormatInt(ae.ValidTo, 10), ae.Sign)

		if ae.ProxyType == "http" {
			bodyStr = fmt.Sprintf(`
			%s
			<div>[%s-%s-2https]</div>
			<div>type=%s</div>
			<div>subdomain=%s</div>
			<div>meta_valid_to=%s</div>
			<div>meta_sign=%s</div>
			<div>plugin=https2http</div>
			<div>plugin_local_addr=http_local_host:http_local_port</div>
			<div>plugin_crt_path=./server.crt</div>
			<div>plugin_key_path=./server.key</div>
			`, bodyStr, ae.ProxyType, ae.ProxyName, ae.ProxyType, ae.ProxyName, strconv.FormatInt(ae.ValidTo, 10), ae.Sign)
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
	} else {
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
		<div>[%s]</div>
		<div>type=%s</div>
		<div>remote_port=%d</div>
		<div>meta_valid_to=%s</div>
		<div>meta_sign=%s</div>
		<div>#local_ip=</div>
		<div>#local_port=</div>
		<div>#use_encryption=false</div>
		<div>#use_compression=false</div>
		</body>
		</html>`, ae.ProxyName, ae.ProxyType, ae.RemotePort, strconv.FormatInt(ae.ValidTo, 10), ae.Sign))
	}

}
