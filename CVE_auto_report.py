from time import sleep
from datetime import datetime, timedelta
import argparse
import re
import ConfigParser
import sys
from basic_create_issue import addcomment_checkqualys
from basic_create_issue import addcomment
from jira import JIRA
import thread
from multiprocessing.connection import Client
import csv
import urllib3
urllib3.disable_warnings()
#const
months = ["January","February","March","April","May","June","July","August","September","October","November","December"]
delay =100
jira = 0

try:
    config = ConfigParser.RawConfigParser()
    config.read('JiraConfig.ini')
    hostjira = config.get('login_config','jira_url').replace("'","")
    Jusername = config.get('login_config','uname').replace("'","")
    Jpassword = config.get('login_config','pwd').replace("'","")
    PROJECT_NAME = config.get('login_config','PROJECT_NAME').replace("'","")
except expression as identifier:
    print("Can't load config. Need a 'JiraConfig.ini' file in this folder")
    sys.exit(0)



def main(done_ticket):
    out_file = ""
    thistime = datetime.today().strftime('%y-%m-%d')
    out_file = str(thistime).replace("-","") + "_"

    try:
        date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        # write_output('bot_jira.log',date_time + ' Waiting Jira task')
        jira_options = {
        'server': hostjira,
        'verify': False
        }
        try:
            # jira = JIRA(basic_auth=(username,username),options=jira_options)
            jira = JIRA(auth=(Jusername,Jpassword),options=jira_options,timeout=30)
            print(jira)
        except Exception as e:
            print(e)
            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            # write_output('bot_jira.log',date_time + ' cannot log in jira, time out')
            sys.exit(0)
        
        havequalys = 0
        block_size = 100
        block_num = done_ticket
        date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        # write_output('bot_jira.log',date_time + ' scanning jira project: '+PROJECT_NAME)
        while True:
            # labels = None
            start_idx = block_num*block_size
            # write_output('bot_jira.log',date_time + ' start scan jira from ticket: '+str(start_idx))
            issues = jira.search_issues('project='+PROJECT_NAME, start_idx, block_size)
            if len(issues) == 0:
            # Retrieve issues until there are no more to come
                break
            block_num += 1
            
            for issue in issues:
                if issue.fields.status.name.upper() != "DONE":
                    labels = issue.fields.labels
                    if 'CVE_Check' in labels:
                        for label_con in labels:
                            if 'CVE' in label_con and 'CVE_Check' not in label_con:
                                print(label_con)
                                filetoupload = label_con+'.csv'
                                print(filetoupload)
                                try:
                                    with open(filetoupload, 'rb') as f:
                                        jira.add_attachment(issue=issue, attachment=f)
                                except Exception, e:
                                    print(str(e))
                                    print('No File')
    except:
        pass

done_ticket = 0                 
done_ticket = main(done_ticket)