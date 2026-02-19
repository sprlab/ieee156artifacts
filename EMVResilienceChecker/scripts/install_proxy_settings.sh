ip=10.192.148.60
port=8080
adb shell settings put global http_proxy $ip:$port
echo "Proxy settings installed for ip $ip and port $port."