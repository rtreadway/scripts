import argparse
from pprint import pp
import boto3

def list_folders_matching_pattern(bucket_name, folder_format_func, prefix=''):
    s3_client = boto3.client('s3')
    paginator = s3_client.get_paginator('list_objects_v2')
    
    folder_names = []
    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix, Delimiter='/'):
        # print(page)
        # print(page.get('CommonPrefixes', []))
        for common_prefixes in page.get('CommonPrefixes', []):
            # print(common_prefixes)
            folder_name = common_prefixes.get('Prefix').rstrip('/')
            # pp(folder_name)
            if folder_format_func(folder_name.split('/')[-1]):
                folder_names.append(folder_name)
    return folder_names

def check_folder_name_format(folder_name):
    import re
    pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}_\d{2}$'
    return bool(re.match(pattern, folder_name))

def consolidate_files(bucket_name, folders):
    s3_client = boto3.client('s3')
    target_folder = folders[0] + '/'
    for folder in folders[1:]:
        for obj in s3_client.list_objects_v2(Bucket=bucket_name, Prefix=folder + '/').get('Contents', []):
            copy_source = {'Bucket': bucket_name, 'Key': obj['Key']}
            new_key = obj['Key'].replace(folder, target_folder, 1)
            s3_client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=new_key)
            s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
            
def enumerate_s3_bucket_structure(bucket_name, prefix, aws_profile):
    session = boto3.Session(profile_name=aws_profile, region_name='us-east-1')
    s3_client = session.client('s3')
    result = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix, Delimiter='/')

    folder_structure = {}

    for content in result.get('CommonPrefixes', []):
        parts = content['Prefix'].strip('/').split('/')
        print(parts)
        env_name = parts[0]
        if len(parts) == 1:
            folder_structure[env_name] = {}
        elif len(parts) == 2:
            timestamp = parts[1]
            if env_name not in folder_structure:
                folder_structure[env_name] = {}
            folder_structure[env_name][timestamp] = enumerate_s3_bucket_structure(bucket_name, content['Prefix'], aws_profile)
        elif len(parts) == 3:
            timestamp, message_type = parts[1], parts[2]
            if env_name not in folder_structure:
                folder_structure[env_name] = {}
            if timestamp not in folder_structure[env_name]:
                folder_structure[env_name][timestamp] = []
            folder_structure[env_name][timestamp].append(message_type)

    return folder_structure

def print_bucket_hierarchy(bucket_name, env_name, aws_profile):
    prefix = f"{env_name}/"
    structure = enumerate_s3_bucket_structure(bucket_name, prefix, aws_profile)
    # Pretty print the structure
    for env, timestamps in structure.items():
        print(f"{env}:")
        for timestamp, message_types in timestamps.items():
            print(f"  {timestamp}:")
            for message_type in message_types:
                print(f"    {message_type}")

def move_files(bucket_name, env_name, folder_name, aws_profile=None):
    '''Used to consolidate files from a bad implementation of filesaving for the simulated messages.\n
    The mistake created a new folder every timestamp update, which was by the minute, so we ended up with many folders of 5 files, rather than one folder with a subfolder containing all files for that run of the message type\n
    This moved those files to the correct place: a message-type folder within the initial timestamp folder created when the process began for that message type'''
    session = boto3.Session(profile_name=aws_profile, region_name='us-east-1')
    s3_client = session.client('s3')

    # These 2 are used to handle variance amongst what "1.5MB" is
    #   That single value reported in AWS console does not reflect the real file bytesizes which approximate *around* 1.5MB, so this helps handle that
    target_size = 1.5 * 1024 * 1024
    tolerance = 10 * 1024 # 10KB variance
    prefix = f"{env_name}/"
    first_timestamp_folder = None # capture the first folder of the enumeration, because in this case it happens to be the folder these files belong in (matching tti msg gen start time)
    continuation_token = None  # for pagination
    # These 3 gather certain useful info & were used before the actual move to review the potential changes
    skipped_files = []
    size_review_files = []
    change_files = {}

    while True:
        if continuation_token:
            objects = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix, ContinuationToken=continuation_token)
        else:
            objects = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

        for obj in objects.get('Contents', []):
            key = obj['Key']
            size = obj['Size']
            # print(f"FILE: Key:{key} | Size: {size}")
            parts = key.split('/')
            # print(parts)
            if len(parts) != 3:  # We only want something like e2e/timestamp/file and not the files residing within 
                skipped_files.append(key)
                continue

            # Determine the first timestamp folder
            if not first_timestamp_folder:
                first_timestamp_folder = parts[1]

            # Check size of the file
            if target_size - tolerance <= size <= target_size + tolerance:  # 1.5MB in bytes
                # Define the new key
                new_key = f"{env_name}/{first_timestamp_folder}/{folder_name}/{parts[-1]}"
                change_files[key] = new_key
                # print(f"NEW KEY{new_key}")
                # Copy the object to the new location
                s3_client.copy_object(Bucket=bucket_name, CopySource={'Bucket': bucket_name, 'Key': key}, Key=new_key)

                # Delete the original object
                s3_client.delete_object(Bucket=bucket_name, Key=key)

            else:
                # Add to the manual review list
                size_review_files.append(key)

        # Check if there are more objects to list
        if objects.get('IsTruncated'):
            continuation_token = objects['NextContinuationToken']
        else:
            break

    return size_review_files, skipped_files, change_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Bucket folder enumeration tool', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--env-name", "-e")
    parser.add_argument('--bucket', '-b', help="Bucket Name")
    parser.add_argument('--prefix', default='', help="Bucket prefix")
    parser.add_argument('--profile', '-p', help="AWS Profile")
    
    args = parser.parse_args()
    print(args)

    boto3.setup_default_session(profile_name=args.profile, region_name='us-east-1')
    env_type = 'prod' if args.env_name in ('prod', 'preprod') else 'nonprod'
    bucket = f"{env_type}-simulated-messages"
    # pp(list_folders_matching_pattern(args.bucket, check_folder_name_format, args.prefix))
    
    # print_bucket_hierarchy(bucket, args.env_name, args.profile)
    # enumerate_s3_bucket_structure(bucket_name=args.bucket, prefix=args.prefix, aws_profile=args.profile)
    size_reviewL, skippedL, changesD = move_files(bucket_name=args.bucket, env_name=args.env_name, folder_name='digital-tti', aws_profile=args.profile)
    print()
    print(size_reviewL)
    print() 
    print(skippedL)
    print()
    pp(changesD)
