#!/bin/bash

count=10
parser=${1:-"AEL"}

for i in $(seq $count); do
    python ${parser}_benchmark.py
done
