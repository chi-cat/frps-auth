"# frps-auth" 

一个简单frps授权；基于frps提供接口NewProxy
* [frp](https://github.com/fatedier/frp)
* [数据库 nutsdb](https://github.com/xujiajun/nutsdb)

### 配置
* 通过后台配置支持的Token和授权时间，只允许 frpc 客户端创建通过鉴权的代理

1. 创建 `frps-auth.ini` 文件。
```
address=0.0.0.0
#frps-auth的运行端口
port=4000
#后台管理用户名
username=admin
#后台管理密码
password=
#签名盐值
salt=
```
2.修改fprs的配置文件 `frps.ini`注册插件并启动。

```
[plugin.port-manager]
addr=0.0.0.0:4000
path=/auth
ops=NewProxy
```

### 后台管理使用
后台访问路径`127.0.0.1:4000`

![image](https://raw.githubusercontent.com/dev-lluo/readme-images/master/list-frps-auth.jpg)
```
标注1 添加
标注2 修改
标注3 删除
标注4 生成授权信息
标注5 临时开关授权
```

1.添加一个授权信息

![image](https://raw.githubusercontent.com/dev-lluo/readme-images/master/add-frps.auth.png)

```
添加一个授权；当类型选择为HTTP时；同时支持https授权；此时端口设置禁用。
```

2.修改一个授权信息

```
修改一个授权；仅支持修改时间和备注
```

3.删除

4.生成授权信息

![image](https://raw.githubusercontent.com/dev-lluo/readme-images/master/info-frps-auth.jpg)
```
#你可以将该信息粘贴到frpc.ini中。
#授权到期时间
meta_auth_valid_to=
#授权key
meta_auth_key=
```


5. 临时开关授权
```
当你只是想临时想关闭某个服务的对外访问时；可以启用
```

### 备注


```
此授权开启后;frpc.ini中对应的代理中meta_auth_valid_to,meta_auth_key不可以被修改
当代理类型为HTTP时，客户端还不可修改subdomain属性
当代理为其他类型时；客户端还不可以修改remote_port,proxy_name和proxy_type属性
```
