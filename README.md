"# frps-auth" 

一个简单frps授权；基于frps提供接口NewProxy
* [frp](https://github.com/fatedier/frp)
* [数据库 nutsdb](https://github.com/xujiajun/nutsdb)

### Release

* [release v0.2](https://github.com/dev-lluo/frps-auth/releases/tag/v0.2)
* [release v0.4.20.beta](https://github.com/dev-lluo/frps-auth/releases/tag/v0.4.20.beta)

### 配置
* 通过后台页面配置授权Token和授权时间，只允许 frpc 客户端创建通过鉴权的代理

1. 创建 `frps-auth.ini` 文件。
```
address=0.0.0.0
#frps-auth的运行端口
port=4000
#后台管理用户名
username=admin
#后台管理密码;此项必填
password=
#签名盐值；此项必填；一个随机字符串
salt=
```
2.修改fprs的配置文件 `frps.ini`注册插件并启动。

```
[plugin.port-manager]
addr=0.0.0.0:4000
path=/auth
ops=NewProxy,Heartbeat
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
添加一个授权；当类型选择为HTTP时；同时支持https授权；此时端口设置禁用,代理名称将成为subdomain。
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

注意；开启禁用后；在frp默认版本上只有在客户端重启或网络链接断开后重新连接时生效;
~~如果需要即时生效；请访问(ping-plugin分支)[https://github.com/dev-lluo/frp/tree/ping-plugin] ;此分支为个人修改版本。~~
~~根据和frp作者大大沟通；在frp的[dev分支](https://github.com/fatedier/frp/tree/dev)上已经加入了类似的api，此功能可能会在dev合并到master分支后发生更改。~~

如果需要即时生效；请访问(heartbeat-plugin分支,基于0.42.0版本)[https://github.com/dev-lluo/frp/tree/heartbeat-plugin] ;此分支为个人修改版本。
ping-plugin分支由于鸽了太久;没有同步主干代码;目前不推荐使用

### 关于为啥同步主干代码后还会有heartbeat-plugin分支
frps主干目前已加入Ping的扩展点,但似乎是基于整个client端的;由客户端与服务器心跳触发;且此消息不会携带meta的扩展属性;
但由于此插件的临时授权开关是基于Proxy的;所以又另外维护了一个heartbeat-plugin分支;由server端主动触发;



### 备注


```
此授权开启后;frpc.ini中对应的代理中meta_auth_valid_to,meta_auth_key不可以被修改
当代理类型为HTTP时，客户端还不可修改subdomain属性
当代理为其他类型时；客户端还不可以修改remote_port,proxy_name和proxy_type属性
```
