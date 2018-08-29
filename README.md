## AuthOTP

golang实现google authencatior服务器RestAPI（密钥生成、OTP生成、OTP认证 ）


####  API 接口

> `/register` 
 
  - 用途： 生成私有密钥（base64编码）
  - 方法: GET
  - 参数:无 
  - 返回：seed密钥（string）


>  `/otp` 

  - 用途： 通过私有密钥，生成OTP一次性密码
  - 方法: POST
  - 参数:   请求体JSON格式  ，`skey` 私有密钥
  - 返回： otp密码 （string）
  
```go
Post Body:
{
"skey":"GI3TSYRWGMZWEZRTMNSGMYRXGFTDSODFGI4DEMRXHE3GKZDBGY2TKM3FMQYWMNDG"
}
```


> `/auth`

  - 用途： 通过私有密钥，生成OTP一次性密码
  - 方法: POST
  - 参数:   请求体JSON格式  ，`skey` 私有密钥 `otp` 需认证的密码
  - 返回： true/false 
  
```go
Post Body:
{
"skey":"GI3TSYRWGMZWEZRTMNSGMYRXGFTDSODFGI4DEMRXHE3GKZDBGY2TKM3FMQYWMNDG",
"otp":"712257"
}
```

