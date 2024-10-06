#!/bin/bash
cd /home/user/Downloads/LogModSec/
echo "Script ran at :$(date)" >> /home/aomsin/Downloads/LogModsec/script_log.txt
javac LogModSec3.java 
export CLASSPATH=mysql-connector-j-8.4.0.jar:.
java LogModSec3

