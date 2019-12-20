import requests
import struct
import base64
requests.packages.urllib3.disable_warnings()
doh_server = 'https://mozilla.cloudflare-dns.com/dns-query'
question_icon = '?dns='
def dobase64(req):
    req = base64.b64encode(req)
    return req
def makedns(domain):
    request_id = 0
    head = struct.pack('!HBBHHHH',request_id,1,0,1,0,0,0)
    body = b''
    for part in domain.split('.'):
        body += struct.pack('!B', len(part)) + struct.pack(f'!{len(part)}s',bytes(part,encoding='utf8'))
    body += struct.pack('!BHH',0,1,1)   
    req = head + body
    req = dobase64(req)
    return req.decode('utf-8'),body
def analyze(res, body):
    (res_request_id,res_flag,res_qdcount,res_ancount,res_nscount,res_arcount) = struct.unpack('!HHHHHH', res[:12])
    answer = res[12+len(body):]
    print('ip地址为:')
    #print(answer)
    if res_ancount == 0:
        print('无')
    for i in range(res_ancount):
        (a_name,a_type,a_class,a_TTL,a_length) = struct.unpack('!HHHIH',answer[:12])
        a_content = answer[12:12+a_length]
        if a_type == 1:
            #print(a_content)
            ip_content = [str(a_content[0]),str(a_content[1]),str(a_content[2]),str(a_content[3])]
            ip = '.'.join(ip_content)
            print(ip)
        answer = answer[12+a_length:]
while True:        
    web = input('请输入要询问的网址:')        
    req_domain,body = makedns(web)
    total_req = doh_server + question_icon + req_domain
    headers = {
    'Accept':'application/dns-message'    
    }
    response = requests.get(total_req, stream=True, verify=False, headers=headers)
    res = response.content
    try:
        analyze(res,body)
    except:
        print('也许是域名输入错误?')

