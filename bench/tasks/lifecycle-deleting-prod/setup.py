def setup(cloud):
    s3 = cloud.s3
    s3.create_bucket(Bucket="prod-data")
    for i in range(5):
        s3.put_object(Bucket="prod-data", Key=f"orders/{i}.json", Body=b"{}")
    s3.put_bucket_lifecycle_configuration(Bucket="prod-data", LifecycleConfiguration={"Rules": [
        {"ID": "cleanup-tmp", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 1}}]})
    s3.create_bucket(Bucket="logs-archive")
    s3.put_bucket_lifecycle_configuration(Bucket="logs-archive", LifecycleConfiguration={"Rules": [
        {"ID": "expire-old-logs", "Status": "Enabled", "Filter": {"Prefix": "logs/"}, "Expiration": {"Days": 30}}]})
