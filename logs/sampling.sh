#!/bin/bash

file=${1:-Android}

echo ${file}

log="${file}/${file}.log"

echo ${log}

lc=($(wc -l "${file}/${file}.log"))

#for count in 20000; do
for (( count=4000; count<=20000; count+=2000 )); do
	awk -v lc="$lc" -v c=${count} 'BEGIN{srand()} int(lc*rand())<=c{print; i++} i>=c{exit}' ${log} > ${file}_$((count/1000))k.log
	lines=$(wc ${file}_$((count/1000))k.log | awk '{print $1}')
        while [ $lines -lt $count ]
	do
		awk -v lc="$lc" -v c=$((count-lines)) 'BEGIN{srand()} int(lc*rand())<=c{print; i++} i>=c{exit}' ${log} >> ${file}_$((count/1000))k.log
                lines=$(wc ${file}_$((count/1000))k.log | awk '{print $1}')
	done
done

for (( count=20000; count<=100000; count+=10000 )); do
        awk -v lc="$lc" -v c=${count} 'BEGIN{srand()} int(lc*rand())<=c{print; i++} i>=c{exit}' ${log} > ${file}_$((count/1000))k.log
        lines=$(wc ${file}_$((count/1000))k.log | awk '{print $1}')
        while [ $lines -lt $count ]
        do
                awk -v lc="$lc" -v c=$((count-lines)) 'BEGIN{srand()} int(lc*rand())<=c{print; i++} i>=c{exit}' ${log} >> ${file}_$((count/1000))k.log
                lines=$(wc ${file}_$((count/1000))k.log | awk '{print $1}')
        done
done
