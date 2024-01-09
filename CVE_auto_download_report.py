#!/usr/bin/env python
# -*- coding: utf-8 -*-
from numpy import NaN
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from time import sleep
from selenium.webdriver.common.keys import Keys
from datetime import datetime, timedelta
import argparse
import configparser
import sys
import pandas as pd
from openpyxl import load_workbook
import os
from jira import JIRA
import csv
import urllib3
urllib3.disable_warnings()
import requests

#const
delay =100
jira = 0
DOWLOAD_LOCATION = '/Users/css-dr-ductq/Downloads'

#load config
try:
    config = configparser.RawConfigParser()
    config.read('QualysConfig.ini')
    username = config.get('DEFAULT','Q_username')
    password = config.get('DEFAULT','Q_password')
except expression as identifier:
    print("Can't load config. Need a 'QualysConfig.ini' file in this folder")
    sys.exit(0)

try:
    config = configparser.RawConfigParser()
    config.read('JiraConfig.ini')
    hostjira = config.get('login_config','jira_url').replace("'","")
    Jusername = config.get('login_config','uname').replace("'","")
    Jpassword = config.get('login_config','pwd').replace("'","")
    PROJECT_NAME = config.get('login_config','PROJECT_NAME').replace("'","")
except expression as identifier:
    print("Can't load config. Need a 'JiraConfig.ini' file in this folder")
    sys.exit(0)

chrome_options = Options()
# chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage') 
# options.binary_location = "/usr/bin/google-chrome"
# prefs = {"download.default_directory" : "/some/path"}
# chrome_options.add_experimental_option("prefs",prefs)
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option('useAutomationExtension', False)

def login_qualys(username, password, pnl):
    #login
    while True:
        try:
            print('Trylogin')
            driver = Chrome(options=chrome_options)
            driver.get('chrome://settings/')
            # driver.execute_script('chrome.settingsPrivate.setDefaultZoom(0.00000001);') #zoom out den 1%
            driver.get("https://qualysguard.qg3.apps.qualys.com/portal-front/module/asset/#tab=assets.asset-list-v2-asset-container")
            
            driver.find_element(By.ID, "ext-comp-1005").send_keys(username)
            driver.find_element(By.ID, "ext-comp-1006").send_keys(password)
            driver.find_element(By.ID, "ext-comp-1006").send_keys(Keys.RETURN)
            myElem = WebDriverWait(driver, delay).until(EC.presence_of_element_located((By.ID, 'ext-comp-1079')))
            # sleep(10)
            if pnl == 'vf':
                driver.get("https://qualysguard.qg3.apps.qualys.com/fo/report/create_scan_report.php?run=13196010") #VF
            if pnl == '3s':
                driver.get("https://qualysguard.qg3.apps.qualys.com/fo/report/create_scan_report.php?run=13460719") #3s
            if pnl == 'es':
                driver.get("https://qualysguard.qg3.apps.qualys.com/fo/report/create_scan_report.php?run=13460720") #es
        
            print("DONE LOGIN")
            # driver.fullscreen_window()
            return driver
            break
        except Exception as e:
            print(str(e))
            # driver.quit()
            
def logout_qualys(driver):
    count = 0
    while count < 10:
        try:   
            sleep(5)
            print('Trylogout')
            driver.get("https://qualysguard.qg3.apps.qualys.com/portal-front/module/asset/#tab=assets.asset-list-v2-asset-container")
            myElem = WebDriverWait(driver, delay).until(EC.presence_of_element_located((By.ID, 'ext-gen31')))
            driver.find_element(By.ID, "ext-gen31").click()
            driver.find_element(By.ID, "ext-gen31").send_keys(Keys.RETURN)
            myElem = WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.ID, 'ext-comp-1006')))
            
            count +=10
        except:
            count +=1         
    print('LOGGED OUT')
    driver.quit()

def download_start(directory, timeout, nfiles=None):
    print("wait download star")
    seconds = 0
    dl_wait = True
    while dl_wait and seconds < timeout:
        dl_wait = True
        files = os.listdir(directory)
        if nfiles and len(files) != nfiles:
            dl_wait = True

        for fname in files:
            if fname.endswith('.crdownload'):
                dl_wait = False

        seconds += 1
    return seconds

def download_wait(directory, timeout, nfiles=None):
    print("wait download finish")
    seconds = 0
    dl_wait = True
    while dl_wait and seconds < timeout:
        dl_wait = False
        files = os.listdir(directory)
        if nfiles and len(files) != nfiles:
            dl_wait = True

        for fname in files:
            if fname.endswith('.crdownload'):
                dl_wait = True

        seconds += 1
    return seconds

def qualys_to_excel(pnl, reported_path):
    with open(reported_path,"rt") as source:
        rdr= csv.reader( source )
        with open("2.csv","wt") as result:
            wtr= csv.writer( result )
            i = 0
            for r in rdr: 
                if i <4:
                    pass 
                else:
                    try:
                        wtr.writerow( (r[29],r[0], r[1], r[2], r[4], r[7], r[10], r[19], r[20], r[22], r[23], r[24], r[25],r[16] ))
                    except:
                        print(r)
                        pass
                i=i+1

    read_file = pd.read_csv (r'2.csv')
    itms = len(read_file)
    print(itms)
    i = 0
    while i < itms:
        # print(i,read_file.loc[i,'Last Detected'])
        if datetime.strptime(read_file.loc[i,'Last Detected'],"%m/%d/%Y %H:%M:%S") < (date_time_now - timedelta(days=14)):
            read_file.drop([i],axis=0,inplace=True)
        i+=1
    print(len(read_file))

    if pnl == 'vf':
        print("start matching owner")
        read_file['Owner']=NaN
        print("load owner")
        danhsachowner  = pd.read_excel (r'danhsachserverVF.xlsx')
        print("done load owner")
        i = 0
        while i < itms:
            try:
                for j in range(len(danhsachowner)):
                    if read_file.loc[i,'IP'] == danhsachowner.loc[j,'IP']:
                        read_file.loc[i,'Owner'] = danhsachowner.loc[j,'Owner']
            except:
                pass
            i+=1

    read_file.to_excel (r'test.xlsx', index = None, header=True)
    os.remove('2.csv')
    os.remove(reported_path)

def find_qualys_file(path):
    for root, dirs, files in os.walk(path):
        for file in files:
            if 'Scan_Report_CSS_report_daily' in file:
                return (os.path.join(root, file))

def do_the_report(pnl):
    driver = 0
    driver = login_qualys(username, password, pnl)
    report_name = 'CSS report daily ' +pnl
    driver.find_element(By.ID, "scan_report_title").send_keys(report_name)
    sleep(10)
    driver.find_element(By.ID, "scan_report_title").send_keys(Keys.RETURN)

    print('DOWNLOADING report file')
    sleep(10)
    try:
        driver.find_element(By.ID, "confirm_btn").click()
    except:
        pass
    # sleep(180)
    download_start(DOWLOAD_LOCATION,100000000)
    download_wait(DOWLOAD_LOCATION,100000000)
    logout_qualys(driver)

    reported = find_qualys_file(DOWLOAD_LOCATION)
    print('report here: '+reported)
    print('START make test.xlsx')
    qualys_to_excel(pnl, reported)
    print('DONE make test.xlsx')

    print('Start upload test.xlsx')
    if pnl == 'vf':
        requests.put("https://files.css.net/remote.php/webdav/Defense/VF/Bao_cao_hang_tuan/Auto_Qualys/vf.xlsx", auth=('ductq', 'taquangduc1'), data=open('test.xlsx', 'rb'))
    if pnl == '3s':
        requests.put("https://files.css.net/remote.php/webdav/Defense/3S/Bao_cao_hang_tuan/Auto_Qualys/3s.xlsx", auth=('ductq', 'taquangduc1'), data=open('test.xlsx', 'rb'))
    if pnl == 'es':    
        requests.put("https://files.css.net/remote.php/webdav/Defense/ES/Bao_cao_hang_tuan/Auto_Qualys/es.xlsx", auth=('ductq', 'taquangduc1'), data=open('test.xlsx', 'rb'))
    print('Done upload test.xlsx')
    os.remove('test.xlsx')
    print('Done remove local test.xlsx')

while True:
    date_time_now = datetime.now()
    pnl = 'vf'
    do_the_report(pnl)
    pnl = '3s'
    do_the_report(pnl)
    pnl = 'es'
    do_the_report(pnl)
    sleep(3600)
