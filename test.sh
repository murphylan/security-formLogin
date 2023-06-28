#!/bin/bash

# 发送请求获取登录页面，并将响应保存到变量中
response=$(curl --cookie-jar cookie -L http://localhost:8080/login)

# 使用sed命令提取CSRF令牌的值
csrf_token=$(echo "$response" | sed -n 's/.*<input name="_csrf" type="hidden" value="\([^"]*\)".*/\1/p')

# 打印CSRF令牌的值
echo "CSRF Token: $csrf_token"

curl --cookie cookie  \
-d "username=user1@abc.com&password=password&_csrf=$csrf_token" \
-i http://localhost:8080/login