'''Simple tool for self-identification in AWS'''
import argparse
import boto3

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WhoAmI AWS tool', formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('--profile', '-p', help="AWS Profile")
    
    args = parser.parse_args()

    boto3.setup_default_session(profile_name=args.profile, region_name='us-east-1')

    # Get the caller identity
    response = boto3.client('sts').get_caller_identity()

    print("User ARN:", response['Arn'])
    print("Account ID:", response['Account'])
    print("User ID:", response['UserId'])
