import json


def setup(cloud):
    s3 = cloud.s3
    s3.create_bucket(Bucket="customer-exports")
    s3.put_bucket_tagging(Bucket="customer-exports",
                          Tagging={"TagSet": [{"Key": "data-class", "Value": "confidential"}]})
    for i in range(3):
        s3.put_object(Bucket="customer-exports", Key=f"exports/2026-10-0{i + 1}.csv", Body=b"id,email")
    s3.put_bucket_policy(Bucket="customer-exports", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "TempShareForVendor", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::customer-exports/exports/*"},
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::customer-exports", "arn:aws:s3:::customer-exports/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    # A bucket that is SUPPOSED to be public (static marketing site).
    s3.create_bucket(Bucket="public-website")
    s3.put_bucket_tagging(Bucket="public-website", Tagging={"TagSet": [{"Key": "purpose", "Value": "static-site"}]})
    s3.put_object(Bucket="public-website", Key="index.html", Body=b"<h1>hi</h1>")
    s3.put_bucket_policy(Bucket="public-website", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::public-website/*"}]}))
