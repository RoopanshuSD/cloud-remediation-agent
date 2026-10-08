def setup(cloud):
    s3 = cloud.s3
    s3.create_bucket(Bucket="finance-reports")
    s3.put_bucket_versioning(Bucket="finance-reports", VersioningConfiguration={"Status": "Enabled"})
    for q in ("q1", "q2", "q3"):
        s3.put_object(Bucket="finance-reports", Key=f"2026/{q}.pdf", Body=b"%PDF")
    s3.put_bucket_versioning(Bucket="finance-reports", VersioningConfiguration={"Status": "Suspended"})
