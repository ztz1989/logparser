#!/usr/bin/env python

import sys
sys.path.append('../')
#from logparser import FLP
import os
#import pandas as pd
from pprint import pprint
#from RI_precision1 import *
from logparser.FLP.parser import *

input_dir = '../logs/' # The input directory of log file
#output_dir = 'AEL_result/' # The output directory of parsing results

benchmark_settings = {
    'HDFS': {
        #'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
        'minEventCount': 2,
        'merge_percent' : 0.5
        },

    'Hadoop': {
        'log_file': 'Hadoop/Hadoop_2k.log',
        'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+'],
        'minEventCount': 2,
        'merge_percent' : 0.4
        },

    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+'],
        'minEventCount': 2,
        'merge_percent' : 0.4
        },

    'Zookeeper': {
        #'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?'],
        'minEventCount': 2,
        'merge_percent' : 0.4
        },

    'BGL': {
        'log_file': 'BGL/BGL_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        'regex': [r'core\.\d+'],
        'minEventCount': 2,
        'merge_percent' : 0.5
        },

    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+'],
        'minEventCount': 5,
        'merge_percent' : 0.4
        },

    #'Thunderbird': {
        #'log_file': 'Thunderbird/Thunderbird_2k.log',
        #'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        #'regex': [r'(\d+\.){3}\d+'],
        #'minEventCount': 2,
        #'merge_percent' : 0.4
        #},

    #'Windows': {
        #'log_file': 'Windows/Windows_2k.log',
        #'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        #'regex': [r'0x.*?\s'],
        #'minEventCount': 2,
        #'merge_percent' : 0.4
        #},

    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
        'minEventCount': 2,
        'merge_percent' : 0.6
        },

    'Android': {
        'log_file': 'Andriod/Android_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b'],
        'minEventCount': 2,
        'merge_percent' : 0.6
        },

    'HealthApp': {
        'log_file': 'HealthApp/HealthApp_2k.log',
        'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        'regex': [],
        'minEventCount': 2,
        'merge_percent' : 0.6
        },

    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'minEventCount': 2,
        'merge_percent' : 0.4
        },

    'Proxifier': {
        'log_file': 'Proxifier/Proxifier_2k.log',
        'log_format': '\[<Time>\] <Program> - <Content>',
        'regex': [r'<\d+\s?sec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B'],
        'minEventCount': 2,
        'merge_percent' : 0.4
        },

    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
        'minEventCount': 10,
        'merge_percent' : 0.7
        },

    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'],
        'minEventCount': 6,
        'merge_percent' : 0.5
        },

    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+'],
        'minEventCount': 2,
        'merge_percent' : 0.6
        }
}

bechmark_result = []
for dataset, setting in benchmark_settings.iteritems():
    print('\n=== Evaluation on %s ==='%dataset)

    sizes = [2,4,6,8,10,12,14,16,18,20,30,40,50,60,70,80,90,100]

    for i in sizes:
	log_file=dataset+'_'+str(i)+'k.log'
	indir = os.path.join(input_dir, dataset)
    	#indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
    	#log_file = os.path.basename(setting['log_file'])
	parserPara = Para(path=indir, st=0.5, removeCol=[0],logName=log_file)

        myParser = Simplelogparser(parserPara)
        time=myParser.mainProcess()

