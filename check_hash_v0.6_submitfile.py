#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ast import Expression
from virus_total_apis import PublicApi as VirusTotalPublicApi 
import zipfile                                              
import tarfile
from pathlib import Path
import hashlib

import argparse
import json
import sys
import time
import glob, os
import hashlib
from basic_create_issue import addnewtask
from basic_create_issue import addcomment_checkhash
from basic_create_issue import addcomment_checkfile
from basic_create_issue import get_reporter
import configparser
from datetime import date
#load config

try:
    config = configparser.RawConfigParser()
    config.read('JiraConfig.ini')
    hostjira = config.get('login_config','jira_url').replace("'","")
    username = config.get('login_config','uname').replace("'","")
    password = config.get('login_config','pwd').replace("'","")
    API_KEY = config.get('login_config','api')
except Expression as identifier:
    print("Can't load config. Need a 'JiraConfig.ini' file in this folder")
    sys.exit(0)

# ===== PARSING COMMAND LINE ARGUMENTS TO SCRIPT =====
desc = '''
-f file luu hash, hoac -d location cua cac file can check
'''
p = argparse.ArgumentParser(description=desc)

# Positional arguments:
p.add_argument('-f','--file', type=str, help='list of hashes')

# Optional arguments:
p.add_argument('-d', '--dir', type=str, default=".", help='folder location')
p.add_argument('-s', '--submit', type=bool, default=False, help='submit file true or false')
p.add_argument('-t', '--taskname', type=str,help='auto generate output file name')
p.add_argument('-p', '--pnl', type=str,help='pnl in db')
args = p.parse_args()

pnl = ''
# print("Files location: " + args.dir)
print("Task name: " +str(args.taskname))
if args.taskname != None:
    outputfile = args.taskname+'.csv'
else:
    outputfile =''

if args.pnl != None:
    pnl = args.pnl

def write_output(filename, string_to_write):
    if filename == '':
        print(string_to_write)
    else:
        f = open(filename, "a+")
        f.write(string_to_write+"\n")
        f.close

def write_output_DB(pnl,string_to_write):
    if pnl == 'vf':
        f = open("Verified_DB.csv", "a+")
        f.write(string_to_write+"\n")
        f.close
    elif pnl == 'es':
        f = open("Verified_DB_vines.csv", "a+")
        f.write(string_to_write+"\n")
        f.close
        
def getListOfFiles(dirName):
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        if entry.endswith(('.png', '.jpg', '.jpeg', '.txt', '.pdf', '.mp3' ,'.mp4', '.DS_Store', '.xml', '.ini', '.htm', '.html', '.mst')):
            continue
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory 
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)
                
    return allFiles

# ====================================================

# ============ ACCESS Virustotal.com API =============
virustotal = VirusTotalPublicApi(API_KEY)
# ====================================================
lines = []
if args.file != None:
# open the file as first command line argument for hash list analysis
    f = open(args.file)
    flines = f.readlines()
    for line in flines:
        print(line)
        fi,hashh = line.split(',')
        lines.append([fi,hashh])
    f.close()
else:
    if args.dir != None:
        # print(filelist)
        # for fi in filelist:
        #     if tarfile.is_tarfile(fi):
        #         print(fi + " is tar file")
        #         # tarfile.Tarfile.extractall(fi)
                
        #     elif zipfile.is_zipfile(fi):
        #         print(fi + " is zip file")
        #         with zipfile.ZipFile(fi, 'r') as zip_ref:
        #             zip_ref.extractall(args.dir+'/'+str(Path(fi).stem))
                
        #calcaule sha1 hash
        BUF_SIZE = 8192  # lets read stuff in 64kb chunks!
        filelist = getListOfFiles(args.dir)
        
        for fi in filelist:
            f = None
            with open(fi, 'rb') as f:
                sha1 = hashlib.sha1()
                while data := f.read(BUF_SIZE):
                    sha1.update(data)
            print(fi, sha1.hexdigest())
            lines.append([fi.replace(args.dir,""),sha1.hexdigest()])

dirty = 0
today = date.today()
caninstall = ""
prefix = str(str(today).encode('utf-8')) + "," + str(args.taskname) + "," 
reporter = get_reporter(hostjira,args.taskname,username,password)
postfix =  reporter + "," + "ductq"
if args.file != None:
    for fi,line in lines:
        # print (lines)
        response = virustotal.get_file_report(line)
        # # Convert json to dictionary:
        json_data = json.loads(json.dumps(response))
        # print(json_data)
        if json_data['response_code'] == 200:
            if json_data['results']['verbose_msg']=="The requested resource is not among the finished, queued or pending scans":
                if args.submit == False:
                    link = "https://www.virustotal.com/gui/search/" + line.rstrip()
                try:
                    caninstall = "User could install"
                    write_output(outputfile,(prefix + caninstall + "," + fi + "," + str(line.rstrip())+","+link+","+"0/68" +","+postfix))
                    write_output_DB(pnl,(prefix + caninstall + "," + fi + "," + str(line.rstrip())+","+link+","+"0/68" +","+postfix))
                    # print(line,link)
                except Exception as identifier:
                    print("error "+ " here? " +str(identifier))

            else:
                # print('sha1 : ' + json_data['results']['sha1'])
                if json_data['results']['positives'] > 0:
                    caninstall = "User could not install"
                    write_output(outputfile,(prefix + caninstall + "," + fi + ","  + str(line.rstrip())+','+str(json_data['results']['permalink'])+','+str(json_data['results']['positives']) +'/' + str(json_data['results']['total'])+ ","+ postfix))
                    write_output_DB(pnl,(prefix + caninstall + "," + fi + ","  + str(line.rstrip())+','+str(json_data['results']['permalink'])+','+str(json_data['results']['positives']) +'/' + str(json_data['results']['total'])+ ","+ postfix))
                    addcomment_checkfile(hostjira,args.taskname,username,password,fi,json_data['results']['permalink'])
                    dirty += 1
                else:
                    try:
                        # print(line)
                        caninstall = "User could install"
                        write_output(outputfile,(prefix + caninstall + "," + fi + ","  + line.rstrip()+","+json_data['results']['permalink'] +","+ str(json_data['results']['positives']) +'/' + str(json_data['results']['total']) +","+ postfix))
                        write_output_DB(pnl,(prefix + caninstall + "," + fi + ","  + line.rstrip()+","+json_data['results']['permalink'] +","+ str(json_data['results']['positives']) +'/' + str(json_data['results']['total']) +","+ postfix))
                    
                    except Exception as identifier:
                        print("error "+ " gothere" +str(identifier))
                        link = "https://www.virustotal.com/gui/search/" + line
    
else:
    for fi,line in lines:
        response = virustotal.get_file_report(line)
        # # Convert json to dictionary:
        json_data = json.loads(json.dumps(response))
        # print(json_data)
        if json_data['response_code'] == 200:
            if json_data['results']['verbose_msg']=="The requested resource is not among the finished, queued or pending scans":
                if args.submit == False:
                    link = "https://www.virustotal.com/gui/search/" + line.rstrip()
                else:
                    if os.stat(fi).st_size < 33554432:
                        try:
                            response2 = virustotal.scan_file(fi)
                            json_data2 = json.loads(json.dumps(response2))
                            link = json_data2['results']['permalink']
                        except Exception as e :
                            print("error? "+ fi + " " +str(e))
                            link = "https://www.virustotal.com/gui/search/" + line.rstrip()
                    else:
                        link = "https://www.virustotal.com/gui/search/" + line.rstrip() + ',' + "file too big"
                try:
                    caninstall = "User could install"
                    write_output(outputfile,(prefix + caninstall + "," + fi + "," + str(line.rstrip())+","+str(link)+","+"0/68" +","+postfix))
                    write_output_DB(pnl,(prefix + caninstall + "," + fi + "," + str(line.rstrip())+","+str(link)+","+"0/68" +","+postfix))
                
                except Exception as identifier:
                    print("error 3 "+ fi + " " +str(identifier))
            else:
                # print('sha1 : ' + json_data['results']['sha1'])
                if json_data['results']['positives'] > 0:
                    caninstall = "User could not install"
                    write_output(outputfile,(prefix + caninstall + "," + fi + ","  + line.rstrip()+','+json_data['results']['permalink']+','+str(json_data['results']['positives']) +'/' + str(json_data['results']['total'])+ ","+ postfix))
                    write_output_DB(pnl,(prefix + caninstall + "," + fi + ","  + line.rstrip()+','+json_data['results']['permalink']+','+str(json_data['results']['positives']) +'/' + str(json_data['results']['total'])+ ","+ postfix))
                    addcomment_checkfile(hostjira,args.taskname,username,password,fi,json_data['results']['permalink'])
                    dirty += 1
                else:
                    try:
                        caninstall = "User could install"
                        write_output(outputfile,(prefix + caninstall + "," + fi + ","  + line.rstrip()+","+json_data['results']['permalink'] +","+ str(json_data['results']['positives']) +'/' + str(json_data['results']['total']) +","+ postfix))
                        write_output_DB(pnl,(prefix + caninstall + "," + fi + ","  + line.rstrip()+","+json_data['results']['permalink'] +","+ str(json_data['results']['positives']) +'/' + str(json_data['results']['total']) +","+ postfix))
                    
                    except Exception as identifier:
                        print("error here? "+ fi + " " +str(identifier))
                        # link = "https://www.virustotal.com/gui/search/" + line
    
        # time.sleep(15) #4 phut 1 query danh cho api free

addcomment_checkhash(hostjira,args.taskname,username,password,dirty,outputfile)
    
