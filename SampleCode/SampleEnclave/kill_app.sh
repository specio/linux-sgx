#!/bin/bash
while(true)
do
echo "killing $1"
kill -10 $1
sec=$(( ( RANDOM % 5 )  + 1 ))
echo "sleeping for $sec sec"
sleep $sec
done
