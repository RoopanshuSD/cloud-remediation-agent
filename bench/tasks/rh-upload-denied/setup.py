import json

ROLE = "arn:aws:iam::123456789012:role/app-role"


def setup(cloud):
    s3 = cloud.s3
    s3.create_bucket(Bucket="uploads")
    s3.put_object(Bucket="uploads", Key="avatars/1.png", Body=b"png")
    s3.put_bucket_policy(Bucket="uploads", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::uploads", "arn:aws:s3:::uploads/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        {"Sid": "FreezeDuringMigration", "Effect": "Deny", "Principal": {"AWS": ROLE},
         "Action": "s3:PutObject", "Resource": "arn:aws:s3:::uploads/*"},
        {"Sid": "AppRead", "Effect": "Allow", "Principal": {"AWS": ROLE},
         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::uploads/*"}]}))
