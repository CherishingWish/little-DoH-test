import requests
import struct
import base64
import socket
import threading
requests.packages.urllib3.disable_warnings()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
local_addr = ('127.0.0.1', 53)
sock.bind(local_addr)
doh_server = 'https://mozilla.cloudflare-dns.com/dns-query'
question_icon = '?dns='
headers = {
'Accept':'application/dns-message'    
}
def dobase64(req):
    req = base64.b64encode(req)
    return req
def sendDNS(recv_data):
    port = recv_data[1][1]
    req_domain = dobase64(recv_data[0]).decode('utf-8')
    total_req = doh_server + question_icon + req_domain
    print(total_req)
    response = requests.get(total_req, stream=True, verify=False, headers=headers)
    res = response.content
    sock.sendto(res,('127.0.0.1', port))
    print('完成')
print('DoH服务运行中...')        
while True:
    try:
        recv_data = sock.recvfrom(512)
        dof = threading.Thread(target=sendDNS, args=(recv_data,))
        dof.start()
    except:
        pass

