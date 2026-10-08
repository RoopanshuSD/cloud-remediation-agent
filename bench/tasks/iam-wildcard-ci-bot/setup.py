import json


def setup(cloud):
    cloud.s3.create_bucket(Bucket="build-artifacts")
    cloud.iam.create_user(UserName="ci-bot")
    cloud.iam.put_user_policy(UserName="ci-bot", PolicyName="ci-access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
