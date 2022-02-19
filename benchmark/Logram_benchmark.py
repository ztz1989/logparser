import sys, os
sys.path.append('../')

from logparser.Logram.DictionarySetUp import dictionaryBuilder
from logparser.Logram.MatchToken import tokenMatch
from logparser.Logram.evaluator import evaluate

import multiprocessing

import time
import psutil
import pandas as pd
from logparser.Logram.OnlineParser import OnlineParser
from datetime import datetime

HDFS_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'  # HDFS log format
Android_format = '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>' #Android log format
Spark_format = '<Date> <Time> <Level> <Component>: <Content>'#Spark log format
Zookeeper_format = '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>' #Zookeeper log format
Windows_format = '<Date> <Time>, <Level>                  <Component>    <Content>' #Windows log format
Thunderbird_format = '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>' #Thunderbird_format
Apache_format = '\[<Time>\] \[<Level>\] <Content>' #Apache format
BGL_format = '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>' #BGL format
Hadoop_format = '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>' #Hadoop format
HPC_format = '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>' #HPC format
Linux_format = '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>' #Linux format
Mac_format = '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>' #Mac format
OpenSSH_format = '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>' #OpenSSH format
OpenStack_format = '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>' #OpenStack format
HealthApp_format = '<Time>\|<Component>\|<Pid>\|<Content>'
Proxifier_format = '\[<Time>\] <Program> - <Content>'

HDFS_Regex = [
        r'blk_(|-)[0-9]+' , # block id
        r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)', # IP
        r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$', # Numbers
]
Hadoop_Regex = [r'(\d+\.){3}\d+']
Spark_Regex = [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+']
Zookeeper_Regex = [r'(/|)(\d+\.){3}\d+(:\d+)?']
BGL_Regex = [r'core\.\d+']
HPC_Regex = [r'=\d+']
Thunderbird_Regex = [r'(\d+\.){3}\d+']
Windows_Regex = [r'0x.*?\s']
Linux_Regex = [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}']
Android_Regex = [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b']
Apache_Regex = [r'(\d+\.){3}\d+']
OpenSSH_Regex = [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+']
OpenStack_Regex = [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+']
Mac_Regex = [r'([\w-]+\.){2,}[\w-]+']
HealthApp_Regex = []
Proxifier_Regex = [r'<\d+\ssec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B']

benchmark_settings = {
    'HDFS': {
        'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
	'doubleThreshold': 15,
	'triThreshold': 10
        },
    'Hadoop': {
        'log_file': 'Hadoop/Hadoop_2k.log',
        'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+'],
	'doubleThreshold': 9,
        'triThreshold': 10
        },
    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>', 
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+'],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'Zookeeper': {
        #'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?'],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'BGL': {
        'log_file': 'BGL/BGL_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        'regex': [r'core\.\d+'],
	'doubleThreshold': 92,
        'triThreshold': 4
        },
    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+'],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'Thunderbird': {
        'log_file': 'Thunderbird/Thunderbird_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+'],
	'doubleThreshold': 35,
        'triThreshold': 32
        },
    'Windows': {
        'log_file': 'Windows/Windows_2k.log',
        'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        'regex': [r'0x.*?\s'],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
	'doubleThreshold': 120,
        'triThreshold': 100
        },
    'Android': {
        'log_file': 'Andriod/Android_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b'],
	'doubleThreshold': 2,
        'triThreshold': 2
        },
    'HealthApp': {
        'log_file': 'HealthApp/HealthApp_2k.log',
        'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        'regex': [],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+'],
	'doubleThreshold': 15,
        'triThreshold': 10
        },
    'Proxifier': {
        'log_file': 'Proxifier/Proxifier_2k.log',
        'log_format': '\[<Time>\] <Program> - <Content>',
        'regex': [r'<\d+\s?sec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B'],
	'doubleThreshold': 500,
        'triThreshold': 470
        },
    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
	'doubleThreshold': 88,
        'triThreshold': 81
        },
    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'],
	'doubleThreshold': 30,
        'triThreshold': 25
        },

    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+'],
	'doubleThreshold': 2,
        'triThreshold': 2
        }
}

Id = multiprocessing.current_process().pid
p = psutil.Process(Id)

#doubleDictionaryList, triDictionaryList, allTokenList = dictionaryBuilder(Andriod_format, 'TestLogs/Android_100M.log', Andriod_Regex)
#tokenMatch(allTokenList,doubleDictionaryList,triDictionaryList,15,10,'Output/')

benchmark_result = []
for dataset, setting in benchmark_settings.iteritems():
    print('\n=== Evaluation on %s ==='%dataset)

    log_file='/root/logparser/logs/'+dataset+'/'+dataset+'_2k.log'
    #indir = os.path.join(input_dir, dataset)

    start_time = datetime.now()

    doubleDictionaryList, triDictionaryList, allTokenList = dictionaryBuilder(setting["log_format"], log_file, [])
    tokenMatch(allTokenList,doubleDictionaryList,triDictionaryList,setting["doubleThreshold"],setting["triThreshold"],'Logram_result/'+dataset)
    f_measure, accuracy = evaluate('/root/logparser/logs/'+dataset+'/'+dataset+'_2k.log_structured.csv', 'Logram_result/'+dataset+'Event.csv')

    end_time = datetime.now()

    mem = psutil.virtual_memory()

    print("F-Measure: ",f_measure, "PA: ", accuracy)
    print('Parsing done. [Time taken: {!s}]'.format(end_time - start_time))

    with open("PT_Logram.txt", "a") as f:
        f.write(dataset+'_2k' + ' ' + str(end_time - start_time) + ' ' + str(mem.total) + ' ' + str(mem.used) + ' ' + str(mem.available) + ' ' + str(mem.percent) + '\n')

    benchmark_result.append([dataset, f_measure, accuracy])

print('\n=== Overall evaluation results ===')
df_result = pd.DataFrame(benchmark_result, columns=['Dataset', 'F1_measure', 'Accuracy'])
df_result.set_index('Dataset', inplace=True)
print(df_result)
df_result.T.to_csv('Logram_benchmark_result.csv')
