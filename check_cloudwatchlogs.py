#!/usr/bin/python
from __future__ import print_function
from __future__ import division
import sys
import boto3
import json
import decimal
import argparse
from boto3.dynamodb.conditions import Key, Attr

# Author Header
__author__ = "Ryan Gelber"
__credits__ = ["Ryan Gelber"]
__license__ = "None"
__version__ = "1.0.1"
__maintainer__ = "Ryan Gelber"
__email__ = "ryangelber@gmail.com"
__status__ = "Production"

#Usage Options
parser = argparse.ArgumentParser()

parser.add_argument('-i', "--instance", required="True", \
                    help='Instance name of relational database')
parser.add_argument('-a', "--arn", required="True",  \
                    help='Use the amazon resource name.')
parser.add_argument('-r', "--region", type=str, default="us-west-2", \
                    help='Use AWS region.')
parser.add_argument('-m', "--metric", type=str, default='cpu', \
                    choices=['cpu','load','mem','disk','processes'],\
                    help='Select the type of metric you want to alert on')
parser.add_argument('-w', "--warning", default=80, type=int, \
                    help='Warning Threshold in Minutes')
parser.add_argument('-c', "--critical", default=90, type=int, \
                    help='Critial Threshold in Minutes')

args = parser.parse_args()

db_instance = args.instance
arn = args.arn
region_name = args.region
alert = args.metric
warn = args.warning
crit = args.critical
session_name = "nagios_monitor"


# Assume IAM role and get session token based off of amazon resource name.
def assume_arn(arn, session_name):
    client = boto3.client('sts')
    role = client.assume_role(
        RoleArn = arn,
        RoleSessionName = session_name,
    )
    assume_arn.session_id = role["Credentials"]["AccessKeyId"]
    assume_arn.session_key = role["Credentials"]["SecretAccessKey"]
    assume_arn.session_token = role["Credentials"]["SessionToken"]

def describe_db_instance(region_name, db_instance):
    # AWS Assume Role and Connect
    describe = boto3.client(
        'rds',
        region_name = region_name,
        aws_access_key_id = assume_arn.session_id,
        aws_secret_access_key = assume_arn.session_key,
        aws_session_token = assume_arn.session_token,
    )
    # Select JSON index by database instaces name
    response = describe.describe_db_instances(
        DBInstanceIdentifier = db_instance,  ### Enter hostname
        Marker = 'string'
    )

    # Parse JSON to retrieve instance ID and log group
    describe_db_instance.resourceid = str(response['DBInstances'][0]['DbiResourceId'])
    describe_db_instance.log_group = str(response['DBInstances'][0]['EnhancedMonitoringResourceArn'])
    describe_db_instance.log_group = describe_db_instance.log_group.split(':')[6]


def fetch_latest_log(region_name):
    # AWS Assume Role and Connect
    logs = boto3.client(
        'logs',
        region_name = region_name,
        aws_access_key_id = assume_arn.session_id,
        aws_secret_access_key = assume_arn.session_key,
        aws_session_token = assume_arn.session_token,
    )
    # Request the latest rds log
    response = logs.get_log_events(
        logGroupName = describe_db_instance.log_group,     #This needs a arg.parse
        logStreamName = describe_db_instance.resourceid,   #This needs a arg.parse
        limit = 1,
        startFromHead = False
    )
    # Parse the log
    fetch_latest_log.message = response['events'][0]['message']
    #print(fetch_latest_log.message)

def alert_cpu(warn, crit):
    json_log = json.loads(fetch_latest_log.message)
    log_type = 'cpuUtilization'
    cpu_user = round(json_log[log_type]['user'])
    cpu_sys = round(json_log[log_type]['system'])
    cpu_iowait = round(json_log[log_type]['wait'])
    cpu_idle = round(json_log[log_type]['idle'])
    cpu_nice = round(json_log[log_type]['nice'])


    if cpu_user >= crit or cpu_sys >= crit or cpu_iowait >= crit or cpu_nice >= crit:
        print (f"CPU CRITICAL: user={cpu_user}% system={cpu_sys}% iowait={cpu_iowait}%"
               f"idle={cpu_idle}% nice={cpu_nice}% | cpu_user={cpu_user}%;{warn};"
               f"{crit} cpu_sys={cpu_sys}%;{warn};{crit} cpu_iowait={cpu_iowait}%;"
               f"{warn};{crit} cpu_idle={cpu_idle}%;{warn};{crit} cpu_nice={cpu_nice}%;"
               f"{warn};{crit}")
        sys.exit(2)
    elif cpu_user >= warn or cpu_sys >= warn or cpu_iowait >= warn or cpu_nice >= warn :
        print (f"CPU WARNING: user={cpu_user}% system={cpu_sys}% iowait={cpu_iowait}%"
               f"idle={cpu_idle}% nice={cpu_nice}% | cpu_user={cpu_user}%;{warn};"
               f"{crit} cpu_sys={cpu_sys}%;{warn};{crit} cpu_iowait={cpu_iowait}%;"
               f"{warn};{crit} cpu_idle={cpu_idle}%;{warn};{crit} cpu_nice={cpu_nice}%;"
               f"{warn};{crit}")
        sys.exit(1)
    else:
        print (f"CPU OK: user={cpu_user}% system={cpu_sys}% iowait={cpu_iowait}%"
               f"idle={cpu_idle}% nice={cpu_nice}% | cpu_user={cpu_user}%;{warn};"
               f"{crit} cpu_sys={cpu_sys}%;{warn};{crit} cpu_iowait={cpu_iowait}%;"
               f"{warn};{crit} cpu_idle={cpu_idle}%;{warn};{crit} cpu_nice={cpu_nice}%;"
               f"{warn};{crit}")
        sys.exit(0)

def alert_load(warn, crit):
    json_log = json.loads(fetch_latest_log.message)
    log_type = 'loadAverageMinute'
    one_min = json_log[log_type]['one']
    five_min = json_log[log_type]['five']
    fifteen_min = json_log[log_type]['fifteen']

    if one_min >= crit or five_min >= crit or fifteen_min >= crit:
        print(f"CRITICAL - load average: {one_min}, {five_min}, {fifteen_min} |"
              f" load1={one_min};{warn};{crit};0 load5={five_min};{warn};{crit};"
              f"0 load15={fifteen_min};{warn};{crit};0")
        sys.exit(2)
    elif one_min >= crit or five_min >= crit or fifteen_min >= crit:
        print(f"WARNING - load average: {one_min}, {five_min}, {fifteen_min} |"
              f" load1={one_min};{warn};{crit};0 load5={five_min};{warn};{crit};"
              f"0 load15={fifteen_min};{warn};{crit};0")
        sys.exit(1)
    else:
        print(f"OK - load average: {one_min}, {five_min}, {fifteen_min} |"
              f" load1={one_min};{warn};{crit};0 load5={five_min};{warn};{crit};"
              f"0 load15={fifteen_min};{warn};{crit};0")
        sys.exit(0)

def alert_mem(warn, crit):
    json_log = json.loads(fetch_latest_log.message)
    log_type = 'memory'
    memory_active = round(json_log[log_type]['active'])
    memory_total = round(json_log[log_type]['total'])
    memory_free = round(json_log[log_type]['free'])
    memory_cached = round(json_log[log_type]['cached'])
    memory_buffers = round(json_log[log_type]['buffers'])
    memory_usage = round((memory_total - memory_free - memory_cached - memory_buffers) / memory_total * 100)
    memory_used = round(memory_total - memory_free - memory_cached - memory_buffers)
    warning = round(memory_total / (warn / 1000))
    critical = round(memory_total / (crit / 1000))

    if memory_usage >= crit:
        print(f"CRITICAL - {memory_usage}% ({memory_used} kB) used | "
              f"TOTAL={memory_total}KB USED={memory_used}KB;{warning};{critical} "
              f"FREE={memory_free}KB CACHES={memory_cached}KB")
        sys.exit(2)
    elif memory_usage >= warn:
        print(f"WARNING - {memory_usage}% ({memory_used} kB) used | "
              f"TOTAL={memory_total}KB USED={memory_used}KB;{warning};{critical} "
              f"FREE={memory_free}KB CACHES={memory_cached}KB")
        sys.exit(1)
    else:
        print(f"OK - {memory_usage}% ({memory_used} kB) used | "
              f"TOTAL={memory_total}KB USED={memory_used}KB;{warning};{critical} "
              f"FREE={memory_free}KB CACHES={memory_cached}KB")
        sys.exit(0)

def alert_disk(warn, crit):
    json_log = json.loads(fetch_latest_log.message)
    log_type = 'fileSys'
    array_count = len(json_log[log_type])
    for i in range(0, array_count):
        # Mount Points
        mount_point = json_log[log_type][i]['mountPoint']

        # Mount Percentage Used
        disk_used_file_precent = json_log[log_type][i]['usedFilePercent']
        disk_used_percent = json_log[log_type][i]['usedPercent']

        # Getting disk size in megabytes for performance data
        disk_total = round((json_log[log_type][i]['total'] / 1000))
        disk_used = round((json_log[log_type][i]['used'] / 1000))
        disk_warn = (disk_total - (disk_total * ((100 - warn) / 100)))
        disk_crit = (disk_total - (disk_total * ((100 - crit) / 100)))

        # Getting files used for performance data
        file_total = round(json_log[log_type][i]['maxFiles'])
        file_used = round(json_log[log_type][i]['usedFiles'])
        file_warn = (file_total - (file_total * ((100 - warn) / 100)))
        file_crit = (file_total - (file_total * ((100 - crit) / 100)))

        # Define exit status list
        exit_status = []

        if disk_used_file_precent >= crit or disk_used_percent >= crit:
            print(f"DISK CRITICAL - free space: {mount_point}"
                  f" files_used={file_used} ({disk_used_file_precent}%)"
                  f" {mount_point} mount_used={disk_used}MB ({disk_used_percent}%)"
                  f" | {mount_point}={disk_used}MB;{disk_warn};{disk_crit};0;{disk_total}")
            exit_status.append(2)
        elif disk_used_file_precent >= warn or disk_used_percent >= warn:
            print(f"DISK WARNING - free space: {mount_point}"
                  f" files_used={file_used} ({disk_used_file_precent}%)"
                  f" {mount_point} mount_used={disk_used}MB ({disk_used_percent}%)"
                  f" | {mount_point}={disk_used}MB;{disk_warn};{disk_crit};0;{disk_total}")
            exit_status.append(1)
        else:
            print(f"DISK OK - free space: {mount_point}"
                  f" files_used={file_used} ({disk_used_file_precent}%)"
                  f" {mount_point} mount_used={disk_used}MB ({disk_used_percent}%)"
                  f" | {mount_point}={disk_used}MB;{disk_warn};{disk_crit};0;{disk_total}")
            exit_status.append(0)

    if 2 in exit_status:
        sys.exit(2)
    elif 1 in exit_status:
        sys.exit(1)
    else:
        sys.exit(0)

def alert_processes(warn, crit):
    json_log = json.loads(fetch_latest_log.message)
    log_type = 'processList'
    array_count = len(json_log[log_type])

    if array_count >= crit:
        print(f"CRITICAL - Process Count: {array_count} | count={array_count}")
        sys.exit(2)
    elif array_count >= warn:
        print(f"WARNING - Process Count: {array_count} | count={array_count}")
        sys.exit(1)
    else:
        print(f"OK - Process Count: {array_count} | count={array_count}")
        sys.exit(0)

def select_alert(alert, crit, warn):
    if alert == 'cpu':
        alert_cpu(warn, crit)
    if alert == 'load':
        alert_load(warn, crit)
    if alert == 'mem':
        alert_mem(warn, crit)
    if alert == 'disk':
        alert_disk(warn, crit)
    if alert == 'processes':
        alert_processes(warn, crit)

if __name__ == "__main__":
    assume_arn(arn, session_name)
    describe_db_instance(region_name, db_instance)
    fetch_latest_log(region_name)
    select_alert(alert, crit, warn)
