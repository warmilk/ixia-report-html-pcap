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
def go():
    response = urllib.request.urlopen('file:///D:/quying-work/pythonProject/assets/1.html', timeout=1)
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
                strike_name = tr.select_one("td:nth-of-type(2)").find('a').text
                #将原始的html里面strike name自带的\n空格\t换行过滤走
                result = re.sub(r'\s', '', strike_name)
                print(result)


if __name__ == '__main__':
    go()

