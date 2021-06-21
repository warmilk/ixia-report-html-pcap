"""
author: warmilk
github: https://github.com/warmilk
"""

import os
import subprocess
import re
import urllib
from bs4 import BeautifulSoup as BeautifulSoup
import requests


"""
读取ixiaBreakPointRrport.html并处理提取出有用的漏洞信息
"""

current_project_path = os.getcwd().replace('\\', '/')
html_path = ''.join(['file:///', current_project_path, '/assets/7.html'])
Tshark_path = "C:/Program Files/Wireshark/tshark.exe"
pcap_path = ''.join([current_project_path, '/assets/7.pcap'])
seq = ('name', 'CVE', 'tuples_protocol', 'tuples_src_ip')
strike = {}
strike = strike.fromkeys(seq)
def go():
    response = urllib.request.urlopen(html_path, timeout=1000)
    html = response.read()
    soup = BeautifulSoup(html, "lxml")
    # 获取html里面所有根据time of strike手动添加了class="strike-table"的table标签,从0开始计数，第12个之后的table才是有用的
    table_list = soup.find_all('table', {'class': 'strike-table'})
    # table_list = soup.select("table:nth-child(n+13)")
    # print(table_list)
    for table in table_list:
        tbody_list = table.find_all('tbody')
        for tbody in tbody_list:
            tr_list = tbody.find_all('tr')
            for tr in tr_list:
                # str.strip()  ： 去除字符串头尾的空格
                strike_name = tr.select_one("td:nth-of-type(2)").find('a').text.strip()
                # 将空格替换为_，Icecast_(<=_2.0.1)_Header_Overwrite_(win32) 的特殊符号处理 Microsoft_IIS:__Form_JScript.asp_XSS
                strike['name'] = re.sub(r'\s', '_', strike_name).replace('<=_', 'less_or_equal').replace('.', '-').replace(':', '').replace('\'', '').replace('/', '-')
                # print(strike['name'])
                strike['CVE'] = tr.select_one("td:nth-of-type(4)>div>a").contents[0]
                # 将原始的html里面strike name自带的\n空格\t换行过滤走，还有cve叫http://seclists.org/lists/bugtraq/1997/Mar/0001.html.rules'也要处理
                strike['CVE'] = re.sub(r'\s', '', strike['CVE'])
                if strike['CVE'].find("http://") != -1:
                    strike['CVE'] = strike['name']
                strike_tuples = tr.select_one("td:nth-of-type(6)>span").contents[0]
                strike['tuples_protocol'] = strike_tuples[0:3]
                # 寻找第一个冒号出现的索引
                first_colon_index = strike_tuples.find(':')
                strike['tuples_src_ip'] = strike_tuples[4:first_colon_index]

                strike_save_path = ''.join([current_project_path, '/result/', strike['name']])
                if not os.path.exists(strike_save_path):
                    os.makedirs(strike_save_path)
                # 生成pacp和rules文件
                file = open(strike_save_path + "/" + strike['CVE'] + ".rules", "w")
                file.write(''.join(['reject ', strike['tuples_protocol'].lower(), ' any any -> any any (msg:"', strike_name, '"; flow:established,to_server;', ' reference:cve,', strike['CVE'][3:], ';', ' classtype:attempted-user;', ')']))
                file.close()
                file = open(strike_save_path + "/" + strike['CVE'] + ".pcap", "w")
                file.close()
                output_path = strike['CVE'] + '.pcap'
                input_path = pcap_path
                command = ''.join([Tshark_path, ' -r ', input_path, ' -Y ', 'ip.addr==', strike['tuples_src_ip'], ' -w ', output_path])
                print(command)
                os.system(command)


if __name__ == '__main__':
    go()

