##import time, threading
##print('本程序将比较单线程和多线程的用时')
##balance = 0
##lock = threading.Lock()
##
##def change_it(n):
##    global balance
##    balance = balance + n
##    balance = balance - n
##
##
##def run_thread1(n):
##    for i in range(2000000):
##        lock.acquire()
##        try:
##            change_it(n)
##        finally:
##            lock.release()
##
##def run_thread2(n):
##    for i in range(1000000):
##        lock.acquire()
##        try:
##            change_it(n)
##        finally:
##            lock.release()
##
##
##balance = 0
##start1 = time.time()
##td = threading.Thread(target=run_thread1, args=(5,))
##td.start()
##td.join()
##end1 = time.time()
##timeuse1 = end1 - start1
##print('balance最终结果是： %d\t单线程用时：%f 秒' % (balance,timeuse1))
##
##balance = 0
##start2 = time.time()
##t1 = threading.Thread(target=run_thread1, args=(5,))
##t2 = threading.Thread(target=run_thread2, args=(5,))
##t1.start()
##t2.start()
##t1.join()
##t2.join()
##end2 = time.time()
##timeuse2 = end2 - start2
##print('balance最终结果： %d\t多线程用时：%f 秒' % (balance,timeuse2))




##import threading
##
##local_school = threading.local()
##
##def process_student():
##    std = local_school.student
##    print('hello, %s (in %s)' % (std, threading.current_thread().name))
##
##def process_thread(name):
##    local_school.student = name
##    process_student()
##
##t1 = threading.Thread(target=process_thread, args=('Alice',), name='Thread-A')
##t2 = threading.Thread(target=process_thread, args=('Bob',), name='Thread-B')
##t1.start()
##t2.start()
##t1.join()
##t2.join()


##import struct
##
##def bmpinfo(s):
##    info = struct.unpack('<ccIIIIIIHH', s)
##    if info[0] == b'B':
##         if info[1] == b'M' or b'A':
##             print('is weitu')
##             print('图片大小为: %d * %d' % (info[-3],info[-4]))
##             print('图片的颜色为:', info[-1])
##           
##bmpinfo(b'\x42\x4d\x38\x8c\x0a\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x80\x02\x00\x00\x68\x01\x00\x00\x01\x00\x18\x00')

##import hashlib

##def calc_md5(password):
##	md5 = hashlib.md5()
##	md5.update('password'.encode('utf-8'))
##	print(md5.hexdigest())
##if __name__ == '__main__':
##    calc_md5('admin')


##db = {
##    'michael': 'd41d8cd98f00b204e9800998ecf8427e', #'123456'
##    'bob': '21218cca77804d2ba1922c33e0151105',     #'888888'
##    'alice': '5f4dcc3b5aa765d61d8327deb882cf99'    #'password'
##}
##
##def md5(password):
##    md5 = hashlib.md5()
##    md5.update('password'.encode('utf-8'))
##    return md5.hexdigest()
##
##def login(user,password):
##    if db.get(user):
##        encrypt_pwd = md5(password)
##        if encrypt_pwd == db[user]:
##            print('right password')
##        else:
##            print('invalued password')
##    else:
##        print('invalued user')
##
##if __name__ == '__main__':
##    user = input('please input your username:')
##    password = input('please input your password:')
##    login(user,password)


##from xml.parsers.expat import ParserCreate
##
##class DefaultSaxHandler(object):
##    def start_element(self, name, attrs):
##        print('sax:start_element: %s, attrs: %s' % (name,attrs))
##
##    def end_element(self,name):
##        print('sax: end_element: %s ' % name)
##
##    def char_data(self, text):
##        print('sax:char_data: %s'  % text)
##
##
##xml = r'''<?xml version="1.0"?>
##<ol>
##    <li><a href="/python">Python</a></li>
##    <li><a href="/ruby">Ruby</a></li>
##</ol>
##'''
##
##handler = DefaultSaxHandler()
##parser = ParserCreate()
##parser.StartElementHandler = handler.start_element
##parser.EndElementHandler = handler.end_element
##parser.CharacterDataHandler = handler.char_data
##parser.Parse(xml)


##from html.parser import HTMLParser
##from html.entities import name2codepoint
##
##class MyHTMLParser(HTMLParser):
##    def handle_starttag(self,tag,attrs):
##        print('<%s>' % tag)
##    def handle_endtag(self,tag):
##        print('</%s>' % tag)
##    def handle_startendtag(self,tag,attrs):
##        print('<%s/>' % tag)
##    def handle_data(self,data):
##        print(data)
##    def handle_comment(self,data):
##        print('<!--', data,'-->')
##    def handle_entityref(self,name):
##        print('&%s;' % name)
##    def handle_charref(self,name):
##        print('&#%s;' % name)
##
##parser = MyHTMLParser()
##parser.feed('''<html>
##<head></head>
##<body>
##<!-- test html parser -->
##    <p>Some <a href=\"#\">html</a> HTML&nbsp;tutorial...<br>END</p>
##</body></html>''')



##from urllib import request
##
##with request.urlopen('https://www.douban.com') as f:
##    data = f.read()
##    print('Status:', f.status, f.reason)
##    for k, v in f.getheaders():
##        print('%s %s' %(k, v))
##    print('Data:',data.decode('utf-8'))
    


##import socket
##
##s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##s.connect(('www.sina.com.cn', 80))
##s.send(b'GET / HTTP/1.1\r\nHOST: www.sina.com.cn\r\nConnection: close\r\n\r\n')
##buffer = []
##while True:
##    d = s.recv(1024)
##    if d:
##        buffer.append(d)
##    else:
##        break
##data = b''.join(buffer)
##s.close()
##header, html = data.split(b'\r\n\r\n', 1)
##print(header.decode('utf-8'))
##with open ('sina.html', 'wb') as f:
##    f.write(html)
##



##from email.mime.text import MIMEText
##
##msg = MIMEText('hello, send by python ...', 'plain', 'utf-8')
##from_addr = input('From:')
##password = input('Password:')
##to_addr = input('To:')
##smtp_server = input('SMTP server:')
##
##import smtplib
##
##server = smtplib.SMTP_SSL(smtp_server, 465)
##server.set_debuglevel(1)
##server.login(from_addr,password)
##server.sendmail(from_addr,[to_addr], msg.as_string())
##server.quit()


##from email import encoders
##from email.header import Header
##from email.mime.text import MIMEText
##from email.utils import parseaddr, formataddr
##import smtplib
##
##def _format_addr(s):
##    name, addr = parseaddr(s)
##    return formataddr((Header(name, 'utf-8').encode(), addr))
##
##from_addr = input('From:')
##password = input('Password:')
##to_addr = input('To:')
##smtp_server = input('SMTP server:')

# -*- coding: utf-8 -*-

##import os, sqlite3
##
##db_file = os.path.join(os.path.dirname(__file__), 'test.db')
##if os.path.isfile(db_file):
##    os.remove(db_file)
##
##conn = sqlite3.connect(db_file)
##cursor = conn.cursor()
##cursor.execute('create table user(id varchar(20) primary key, name varchar(20), score int)')
##cursor.execute(r"insert into user values ('A-001', 'Adam', 95)")
##cursor.execute(r"insert into user values ('A-002', 'Bart', 62)")
##cursor.execute(r"insert into user values ('A-003', 'Lisa', 78)")
##cursor.close()
##conn.commit()
##conn.close()
##
##def get_score_in(low, high):
##     try:
##        conn = sqlite3.connect(db_file)
##        cursor = conn.cursor()
##        cursor.execute('select * from user where score between ? and ? order by score', (low,high))
##        values = cursor.fetchall()
##        name = [x[1] for x in values]
##        print(name)
##        return name 
##     except Exception:
##         print(Exception)
##     finally:
##         cursor.close()
##         conn.close()
##        
##
##
##
##assert get_score_in(60, 80) == ['Bart', 'Lisa'], get_score_in(60, 80)
##assert get_score_in(60, 100) == ['Bart', 'Lisa', 'Adam'], get_score_in(60, 100)  


##from sqlalchemy import Column, String, create_engine
##from sqlalchemy.orm import sessionmaker
##from sqlalchemy.ext.declarative import declarative_base
##
##Base = declarative_base()
##
##class User(Base):
##    __tablename__ = 'user'
##    id = Column(string(20), primary_key=True)
##    name = Column(string(20))
##
##class Person(Base):
##    __tablename__ = 'person'
##    id = Column(string(20), primary_key = True)
##    name = Column(string(20))
##    age = Column(int)
##
##engine = create_engine('mysql+mysqlconnector://root:password@localhost:3306/test')
##DBSession = sessionmaker(bind = engine)
##
##session = DBSession()
##new_user = User(id = '5', name = 'jack')
##new_person = Person(id = '1', name = 'tom', age = '20')
##session.add(new_user)
##session.add(new_person)
##session.commit()
##session.close()
##
##session = DBSession()
##user = session.query(User).filter(User.id == '5').one()
##print('type:',type(user))
##print('name:',user.name)
##session.close()
'''
yield 语句是一个生成器表达式，通过send（msg）或next（）语句可对其进行调用
调用机制：第一次调用是使用next()或sned(None),不能使用send发送一个非None值，
因为python yiled没有语句来接收这个值。第一次执行c.send(None),启动生成器，
consumer函数执行到n = yield r后跳出生成器，此时n未有定义，r为'';
跳出生成器执行produce函数循环函数，n = 1，print执行，执行r = c.send(1)，
调用生成器，从 n = yield r 之后继续执行，此时n =1， c.send(1)返回值为consumer
中的r，结果就是r = c.send(1)--》r ='200 OK',在执行print语句，再循环
'''

##def consumer():
##    r = ''  
##    while True:    
##        n = yield r     
##        if not n:
##            return
##        print('[CONSUMER] Comsuming %s..' % n)
##        r = '200 OK' 
##
##def produce(c):
##    c.send(None)    
##    n = 0
##    while n < 5:
##        n = n + 1
##        print('[PRODUCER] Producing %s...' % n)
##        r = c.send(n)
##        print('[PRODUCER] Consumert return: %s' % r)
##    c.close()
##
##c = consumer()
##produce(c)    





##import asyncio
##import threading
##
##@asyncio.coroutine
##def hello():
##    print("Hello world! (%s)" % threading.currentThread())
##    r = yield from asyncio.sleep(1)
##    print("Hello again! (%s)" % threading.currentThread())
##
##loop = asyncio.get_event_loop()
##tasks = [hello(), hello()]
##loop.run_until_complete(asyncio.wait(tasks))
##loop.close()

import asyncio

@asyncio.coroutine
def wget(host):
    print('wget %s ..' % host)
    connect = asyncio.open_connection(host,80)
    reader,writer = yield from connect
    header = 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % host
    writer.write(header.encode('utf-8'))
    yield from writer.drain()
    while True:
        line = yield from reader.readline()
        if line == b'\r\n':
            break
        print('%s header > %s' % (host, line.decode('utf-8')))
    writer.close()

loop = asyncio.get_event_loop()
tasks = [wget(host) for host in ['www.sina.com.cn', 'www.sohu.com', 'www.163.com']]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
