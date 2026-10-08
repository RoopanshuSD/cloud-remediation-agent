def setup(cloud):
    ec2 = cloud.ec2
    app = ec2.create_security_group(GroupName="app-sg", Description="app tier")["GroupId"]
    db = ec2.create_security_group(GroupName="db-sg", Description="postgres")["GroupId"]
    bastion = ec2.create_security_group(GroupName="bastion-sg", Description="ops bastion")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=app, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    # The real fault: this morning's change typed 5433 instead of 5432.
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5433, "ToPort": 5433, "UserIdGroupPairs": [{"GroupId": app}]}])
    # The decoy: looks alarming, unrelated to the symptom.
    ec2.authorize_security_group_ingress(GroupId=bastion, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
