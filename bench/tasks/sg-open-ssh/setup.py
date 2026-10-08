def setup(cloud):
    ec2 = cloud.ec2
    gid = ec2.create_security_group(GroupName="app-sg", Description="app tier")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
