#!/usr/bin/env python

import sys
sys.path.append('../')
from logparser import LogMine, evaluator
import os
import pandas as pd

input_dir = '../logs/' # The input directory of log file
output_dir = 'LogMine_result/' # The output directory of parsing results

benchmark_settings = {
<<<<<<< HEAD
    #'HDFS': {
        #'log_file': 'HDFS/HDFS_2k.log',
        #'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        #'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
        #'max_dist': 0.005,
        #'k': 1,
        #'levels': 2
        #},
=======
    'HDFS': {
        'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
        'max_dist': 0.005,
        'k': 1,
        'levels': 2
        },
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0

    #'Hadoop': {
        #'log_file': 'Hadoop/Hadoop_2k.log',
        #'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>', 
        #'regex': [r'(\d+\.){3}\d+'],
        #'max_dist': 0.005,
        #'k': 1,
        #'levels': 2
        #},

    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+'],
        'max_dist': 0.01,
        'k': 1,
        'levels': 2
        },

    'Zookeeper': {
        'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?'],
        'max_dist': 0.001,
        'k': 1,
        'levels': 2
        },

    #'BGL': {
        #'log_file': 'BGL/BGL_2k.log',
        #'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        #'regex': [r'core\.\d+'],
        #'max_dist': 0.01,
        #'k': 2,
        #'levels': 2
        #},

<<<<<<< HEAD
    #'HPC': {
        #'log_file': 'HPC/HPC_2k.log',
        #'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        #'regex': [r'=\d+'],
        #'max_dist': 0.0001,
        #'k': 0.8,
        #'levels': 2
        #},
=======
    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+'],
        'max_dist': 0.0001,
        'k': 0.8,
        'levels': 2
        },
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0

    #'Thunderbird': {
        #'log_file': 'Thunderbird/Thunderbird_2k.log',
        #'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        #'regex': [r'(\d+\.){3}\d+'],
        #'max_dist': 0.005,
        #'k': 1,
        #'levels': 2
        #},

    #'Windows': {
        #'log_file': 'Windows/Windows_2k.log',
        #'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        #'regex': [r'0x.*?\s'],
        #'max_dist': 0.003,
        #'k': 1,
        #'levels': 2
        #},

    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
        'max_dist': 0.006,
        'k': 1,
        'levels': 2
        },

    'Android': {
        'log_file': 'Android/Android_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b'],
        'max_dist': 0.01,
        'k': 1     ,
        'levels': 2
        },

    #'HealthApp': {
        #'log_file': 'HealthApp/HealthApp_2k.log',
        #'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        #'regex': [],
        #'max_dist': 0.008,
        #'k': 1,
        #'levels': 2
        #},

<<<<<<< HEAD
    #'Apache': {
        #'log_file': 'Apache/Apache_2k.log',
        #'log_format': '\[<Time>\] \[<Level>\] <Content>',
        #'regex': [r'(\d+\.){3}\d+'],
        #'max_dist': 0.005,
        #'k': 1,
        #'levels': 2
        #},
=======
    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'max_dist': 0.005,
        'k': 1,
        'levels': 2
        },
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0

    #'Proxifier': {
        #'log_file': 'Proxifier/Proxifier_2k.log',
        #'log_format': '\[<Time>\] <Program> - <Content>',
        #'regex': [r'<\d+\ssec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B'],
        #'max_dist': 0.002,
        #'k': 1,
        #'levels': 2
        #},

<<<<<<< HEAD
    #'OpenSSH': {
        #'log_file': 'OpenSSH/OpenSSH_2k.log',
        #'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        #'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
        #'max_dist': 0.001,
        #'k': 1,
        #'levels': 2
        #},
=======
    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
        'max_dist': 0.001,
        'k': 1,
        'levels': 2
        },
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0

    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'],
        'max_dist': 0.001,
        'k': 0.1,
        'levels': 2
        },

<<<<<<< HEAD
    #'Mac': {
        #'log_file': 'Mac/Mac_2k.log',
        #'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        #'regex': [r'([\w-]+\.){2,}[\w-]+'],
        #'max_dist': 0.004,
        #'k': 1,
        #'levels': 2
        #},
=======
    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+'],
        'max_dist': 0.004,
        'k': 1,
        'levels': 2
        },
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0
}

bechmark_result = []
for dataset, setting in benchmark_settings.iteritems():
    print('\n=== Evaluation on %s ==='%dataset)

<<<<<<< HEAD
    sizes = [2,4,6,8,10,12,14,16,18,20,30,40,50] #,60,70,80,90,100]
=======
    sizes = [2,4,6,8,10,12,14,16,18,20,30,40,50,60,70,80,90,100]
>>>>>>> 23b20667430e08c60d54d37065b273716a0213f0

    for i in sizes:
	log_file=dataset+'_'+str(i)+'k.log'
        indir = os.path.join(input_dir, dataset)
	#indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
    	#log_file = os.path.basename(setting['log_file'])

    	parser = LogMine.LogParser(log_format=setting['log_format'], indir=indir, outdir=output_dir, 
                               rex=setting['regex'], max_dist=setting['max_dist'], k=setting['k'], 
                               levels=setting['levels'])
    	parser.parse(log_file)

	'''
    	F1_measure, accuracy = evaluator.evaluate(
                           groundtruth=os.path.join(indir, log_file + '_structured.csv'),
                           parsedresult=os.path.join(output_dir, log_file + '_structured.csv')
                           )
    	bechmark_result.append([dataset, F1_measure, accuracy])
	'''
'''
print('\n=== Overall evaluation results ===')
df_result = pd.DataFrame(bechmark_result, columns=['Dataset', 'F1_measure', 'Accuracy'])
df_result.set_index('Dataset', inplace=True)
print(df_result)
df_result.T.to_csv('LogMine_bechmark_result.csv')
'''
