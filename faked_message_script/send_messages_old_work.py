import os
import sys
import json
import argparse
import logging

import boto3
from hyperloop_send_helper import get_queue_url
from replay_eventlake_messages import get_acct_num
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lambda", "common", "python"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lambda", "hyperloop"))
from common import build_hyperloop_message

def send_hyperloop_messages_from_file(file_name, queue_url, queue_resource, timestamp_mode, msg):
    logging.info("Sending messages in file '%s' to queue '%s'" % (file_name, queue_url))
    # Read file
    # with open(file_name, 'r') as file:
    #     messageL = json.load(file)
    
    # Send messages
    # for i, record in enumerate(messageL, 1):
    #     # print(record)
    #     print(json.dumps({"Message": json.dumps(record), "timestampMode": timestamp_mode}))
    queue_resource.send_message(MessageBody=json.dumps({"Message": json.dumps(msg)}))
        # if i % 100 == 0:
        #     logging.info("Sent %d message" % (i))
    logging.info("Finished: Sent message")
    

def parse_tti(tti_msg):
    print(tti_msg)
    header = tti_msg['header']
    event_category = header['event']['category']
    event_name = header['event']['name']
    env_name = header['cb']['env']
    tti_info = [{k: str(v) if k != 'questionCd' else v for k, v in entry.items()} for entry in tti_msg['body']['ttiInfo']]
    body = {
        'testTakerId': header['cb']['userIdentity']['personId'],
        'asmtEventId': '2253',
        'rosterEntryId': tti_msg['body']['rosterEntryId'],
        'ttiInfo': tti_info
    }
    return event_category, event_name, env_name, body

def iter_over_message_list(input_file):
    with open(input_file, 'r') as input:
        fileL = json.load(input)
        
        for msgD in fileL:
            event_category, event_name, env_name, body = parse_tti(msgD)
            yield build_hyperloop_message(bodyD=body, event_category=event_category, event_name=event_name, env_name=env_name)[0]

# def get_queue_url(env_name, queue_type):
#     # TODO: this is broken
#     with open(os.path.join(os.path.dirname(__file__), "..", "lambda", "serverless", "stage_vars", env_name + ".yml")) as f:
#         yaml_data = yaml.safe_load(f)
#     return 'https://sqs.%s.amazonaws.com/%s/%s-%s-nm-%s-internal-queue' % (yaml_data["awsRegion"], yaml_data["awsAccountId"], yaml_data["envName"], "rdl-nmsqt", queue_type)

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s - %(name)s - %(message)s', level=logging.INFO)
    
    parser = argparse.ArgumentParser(description='Publish Simulated Hyperloop Message')
    
    parser.add_argument("file_name", help='File containing messages')
    parser.add_argument("--env-name", default=None, help='The environment name (ie dev, qa, perf, prod, etc) of the queue')
    parser.add_argument("--queue-type", default=None, choices=['student-participant', 'digital-tti', 'digitial-scores', 'holds-status', 'reg'], help='The type of queue')
    parser.add_argument("--queue-url", nargs="+", default=None, help='The queue to send to')
    parser.add_argument("--timestamp-mode", default="newer-when-equal", choices=["newer-when-equal", "older-when-equal", "force-message-timestamp"], help='How to handle timestamps in the message processing')
    parser.add_argument("--asmt-event-id")
    parser.add_argument("--admin_year", default=2023, help='The admin year, default is currently 2023')
    parser.add_argument("--profile", "-p", action='store', default=None, help='The AWS Profile to use')
    
    args = parser.parse_args()
    
    if args.queue_url and args.queue_type:
        logging.error("You can't specify both a queue-url and a queue-type")
        exit(1)
    elif not args.queue_url and not (args.queue_type and args.env_name):
        logging.error("Must either specify a queue type and environment name, or a queue url")
        exit(1)
    
    if args.queue_url:
        queueL = args.queue_url
    elif args.queue_type:
        acct_num = get_acct_num(args.profile)
        queueL = [get_queue_url(env_name=args.env_name, account_id=acct_num, queue_type=args.queue_type, admin_year=args.admin_year)]
        print(queueL)
    else:
        logging.info("Please provide either queue-url(s) or the queue-type")
    
    
    iterator = iter_over_message_list('tti.json')
    for msg in iterator:
        print(f"\nMSG: {msg}")
        queue_resource = boto3.Session(profile_name=args.profile).resource('sqs', region_name='us-east-1').Queue(queueL[0])
        send_hyperloop_messages_from_file(args.file_name, queueL[0], queue_resource, args.timestamp_mode, msg)