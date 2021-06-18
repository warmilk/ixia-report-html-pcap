"""
author: warmilk
github: https://github.com/warmilk
"""


import os
import subprocess
from bs4 import BeautifulSoup as BS
import requests


# 读取ixiaBreakPointRrport.html并处理提取出有用的漏洞信息
def html_to_pylist(localHtmlUrl):
    htmlRes = requests.get(localHtmlUrl)
    # res.apparent_encoding  是从内容中分析出的response的编码方式
    htmlRes.encoding = htmlRes.apparent_encoding
    html = htmlRes.text  # res.text 为字符串方式的响应体，会自动根据响应头部的字符编码进行解码
    all_soup = BS(html, "lxml") # beautifulSoup靓汤，bs是一个用来从HTML或者XML中提取数据的库，源HTML就是一锅乱炖的汤，用了lxml这个解析库之后，就可以通过soup.tagName的方式去获取到HTML的dom节点的数据



def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
