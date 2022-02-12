# -*- coding: utf-8 -*-
#!/usr/bin/env python

import sys

sys.path.append('../')

from logparser.SwissLog.layers.file_output_layer import FileOutputLayer
from logparser.SwissLog.layers.knowledge_layer import KnowledgeGroupLayer
from logparser.SwissLog.layers.mask_layer import MaskLayer
from logparser.SwissLog.layers.tokenize_group_layer import TokenizeGroupLayer
from logparser.SwissLog.layers.dict_group_layer import DictGroupLayer


from logparser.SwissLog.evaluator import evaluator
import os
import re
import string
import hashlib
from datetime import datetime
from tqdm import tqdm
import pandas as pd
import argparse

input_dir = '../logs/' # The input directory of log file
output_dir = 'SwissLog_result/' # The output directory of parsing results


def load_logs(log_file, regex, headers):
    """ Function to transform log file to dataframe
    """
    log_messages = dict()
    linecount = 0
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as fin:
        for line in tqdm(fin.readlines(), desc='load data'):
            try:
                linecount += 1
                match = regex.search(line.strip())
                message = dict()
                for header in headers:
                    message[header] = match.group(header)
                message['LineId'] = linecount
                log_messages[linecount] = message
            except Exception as e:
                pass
    return log_messages

def generate_logformat_regex(logformat):
    """ Function to generate regular expression to split log messages
    """
    headers = []
    splitters = re.split(r'(<[^<>]+>)', logformat)
    regex = ''
    for k in range(len(splitters)):
        if k % 2 == 0:
            splitter = re.sub(' +', '\\\s+', splitters[k])
            regex += splitter
        else:
            header = splitters[k].strip('<').strip('>')
            regex += '(?P<%s>.*?)' % header
            headers.append(header)
    regex = re.compile('^' + regex + '$')
    return headers, regex

'''
benchmark_settings = {
    'HDFS': {
        'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?']
        },

    'Hadoop': {
        'log_file': 'Hadoop/Hadoop_2k.log',
        'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+']
        },

    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+']
        },

    'Zookeeper': {
        'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?']
        },

    'BGL': {
        'log_file': 'BGL/BGL_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        'regex': [r'core\.\d+']
        },

    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+']
        },

    #'Thunderbird': {
        #'log_file': 'Thunderbird/Thunderbird_2k.log',
        #'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        #'regex': [r'(\d+\.){3}\d+']
        #},

    #'Windows': {
        #'log_file': 'Windows/Windows_2k.log',
        #'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        #'regex': [r'0x.*?\s']
        #},
'''

benchmark_settings = {
    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}']
        },

    'Android': {
        'log_file': 'Android/Android_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b']
        },

    'HealthApp': {
        'log_file': 'HealthApp/HealthApp_2k.log',
        'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        'regex': []
        },

    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+']
        },

    'Proxifier': {
        'log_file': 'Proxifier/Proxifier_2k.log',
        'log_format': '\[<Time>\] <Program> - <Content>',
        'regex': [r'<\d+\s?sec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B']
        },
    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+', r'(\d+\.){3}\d+']
        },

    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\s\d+\s']
        },
    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+']
        }
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dictionary', default='../logparser/SwissLog/EngCorpus.pkl', type=str)
    args = parser.parse_args()
    corpus = args.dictionary

    benchmark_result = []
    for dataset, setting in benchmark_settings.items():
     print('\n=== Evaluation on %s ==='%dataset)
     sizes = [2,4,6,8,10,12,14,16,18,20,30,40,50,60,70,80,90,100]

     for i in sizes:
        log_file=dataset+'_'+str(i)+'k.log'
        indir = os.path.join(input_dir, dataset)

        filepath = os.path.join(indir, log_file)
        print('Parsing file: ' + filepath)
        starttime = datetime.now()
        headers, regex = generate_logformat_regex(setting['log_format'])
        log_messages = load_logs(filepath, regex, headers)
        # preprocess layer
        log_messages = KnowledgeGroupLayer(log_messages).run()
        # tokenize layer
        log_messages = TokenizeGroupLayer(log_messages, rex=setting['regex']).run()
        # dictionarize layer and cluster by wordset
        dict_group_result = DictGroupLayer(log_messages, corpus).run()
        # apply LCS and prefix tree
        results, templates = MaskLayer(dict_group_result).run()
        output_file = os.path.join(output_dir, log_file)
        # output parsing results
        FileOutputLayer(log_messages, output_file, templates, ['LineId'] + headers).run()

        endtime = datetime.now()
        print('Parsing done. [Time taken: {!s}]'.format(endtime - starttime))

        with open("PT_SwissLog.txt", "a") as f:
               f.write(os.path.basename(log_file).split('.')[0]+' '+str(endtime - starttime)+'\n')
