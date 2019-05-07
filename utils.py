import boto3
from botocore.client import Config
import os


def save_to_s3(path, name, bucket=''):
    ACCESS_KEY_ID = os.environ['ACCESS_KEY_ID']
    ACCESS_SECRET_KEY = os.environ['ACCESS_SECRET_KEY']
    BUCKET_NAME = bucket

    data = open(path, 'rb')

    s3 = boto3.resource(
        's3',
        aws_access_key_id=ACCESS_KEY_ID,
        aws_secret_access_key=ACCESS_SECRET_KEY,
        config=Config(signature_version='s3v4')
    )
    s3.Bucket(BUCKET_NAME).put_object(Key=name, Body=data)
