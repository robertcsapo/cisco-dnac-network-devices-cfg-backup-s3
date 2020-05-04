
import boto3
import os


def identify(provider):
    """ Return both Provider Name and Provider Settings in a dict """
    s3 = {}
    """ Supported Providers """
    if provider.lower() == "aws":
        s3["provider"] = aws(os.environ)
        s3["name"] = "Amazon Web Services S3"
        s3["bucket"] = os.environ["S3BUCKET"]
        return(s3)
    if provider.lower() == "gcp":
        s3["provider"] = gcp(os.environ)
        s3["name"] = "Google Cloud Storage"
        s3["bucket"] = os.environ["S3BUCKET"]
        return(s3)
    if provider.lower() == "do":
        s3["provider"] = do(os.environ)
        s3["name"] = "DigitalOcean Spaces"
        s3["bucket"] = os.environ["S3BUCKET"]
        s3["url"] = os.environ["ENDPOINT_URL"]
        return(s3)
    if provider.lower() == "minio":
        s3["provider"] = minio(os.environ)
        s3["name"] = "MinIO Inc."
        s3["bucket"] = os.environ["S3BUCKET"]
        s3["url"] = os.environ["ENDPOINT_URL"]
        return(s3)
    """ Return None if provider isn't supported """
    if provider is None:
        return


def aws(environ):
    boto_session = boto3.session.Session()
    s3 = boto_session.client(
                            "s3",
                            aws_access_key_id=environ["AWS_ACCESS_KEY"],
                            aws_secret_access_key=environ["AWS_SECRET_KEY"]
                            )
    return(s3)


def gcp(environ):
    boto_session = boto3.session.Session()
    s3 = boto_session.client(
                            "s3",
                            endpoint_url="https://storage.googleapis.com",
                            aws_access_key_id=environ["AWS_ACCESS_KEY"],
                            aws_secret_access_key=environ["AWS_SECRET_KEY"]
                            )
    return(s3)


def do(environ):
    boto_session = boto3.session.Session()
    s3 = boto_session.client(
                            "s3",
                            endpoint_url=environ["ENDPOINT_URL"],
                            aws_access_key_id=environ["AWS_ACCESS_KEY"],
                            aws_secret_access_key=environ["AWS_SECRET_KEY"]
                            )
    return(s3)


def minio(environ):
    boto_session = boto3.session.Session()
    s3 = boto_session.client(
                            "s3",
                            endpoint_url=environ["ENDPOINT_URL"],
                            aws_access_key_id=environ["AWS_ACCESS_KEY"],
                            aws_secret_access_key=environ["AWS_SECRET_KEY"]
                            )
    return(s3)
