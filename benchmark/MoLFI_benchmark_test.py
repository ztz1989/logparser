#!/usr/bin/env python

import sys
sys.path.append('../')
from logparser import MoLFI, evaluator
import os
import pandas as pd


input_dir = '../logs/' # The input directory of log file
output_dir = 'MoLFI_result/' # The output directory of parsing results

benchmark_settings={
    'Linux': {
        'log_file': 'Linux/Linux_4k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}']
        },
}

bechmark_result = []
for dataset, setting in benchmark_settings.items():
    print('\n=== Evaluation on %s ==='%dataset)
    indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
    log_file = os.path.basename(setting['log_file'])

    parser = MoLFI.LogParser(log_format=setting['log_format'], indir=indir, outdir=output_dir, rex=setting['regex'])
    parser.parse(log_file)

    F1_measure, accuracy = evaluator.evaluate(
                           groundtruth=os.path.join(indir, log_file + '_structured.csv'),
                           parsedresult=os.path.join(output_dir, log_file + '_structured.csv')
                           )
    bechmark_result.append([dataset, F1_measure, accuracy])


print('\n=== Overall evaluation results ===')
df_result = pd.DataFrame(bechmark_result, columns=['Dataset', 'F1_measure', 'Accuracy'])
df_result.set_index('Dataset', inplace=True)
print(df_result)
df_result.T.to_csv('MoLFI_bechmark_result.csv')
