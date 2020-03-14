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
	fmt.Sprintf("{%s,%s}", text, "salt")
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
	key := fmt.Sprintf("%s-%s-%d", aa.ProxyType, aa.ProxyName, aa.RemotePort)
	preSign := fmt.Sprintf("__pt:%s__,__pn:%s__,__rp:%d__,__vt:%s__", aa.ProxyType, aa.ProxyName, aa.RemotePort, strconv.FormatInt(aa.ValidTo, 10))
	sign := SignMD5(preSign)
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
			preSign := fmt.Sprintf("__pt:%s__,__pn:%s__,__rp:%d__,__vt:%s__", ae.ProxyType, ae.ProxyName, ae.RemotePort, strconv.FormatInt(ae.ValidTo, 10))
			ae.Sign = SignMD5(preSign)

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
	fmt.Fprint(w, fmt.Sprintf(`<html>
<head>
<title>授权信息</title>
</head>
<body>
meta_valid_to=%s</br>
meta_sign=%s
</body>
</html>`, strconv.FormatInt(ae.ValidTo, 10),ae.Sign))
}
