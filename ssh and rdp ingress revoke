import json
import boto3

def lambda_handler(event, context):
    ec2_client = boto3.client('ec2')
    security_groups = ec2_client.describe_security_groups()
    try:
        for key, value in security_groups.items():
            for index in range(len(value)):                            #loop through the number of security groups in the account(s).
                ip_permissions = value[index].get('IpPermissions')     #get the inbound traffic rules on the security groups.
                for ip_permission in range(len(ip_permissions)):       #loop through the inbound traffic rules to get variables.
                    from_port = ip_permissions[ip_permission].get('FromPort')
                    to_port = ip_permissions[ip_permission].get('ToPort')
                    ip_range = ip_permissions[ip_permission].get('IpRanges')
                    ipv6 = ip_permissions[ip_permission].get('Ipv6Ranges')
                    group_id = value[index].get('GroupId')
                    if (from_port == 22 and (ip_range == [{'CidrIp':'0.0.0.0/0'}] or ipv6 == [{'CidrIpv6': '::/0'}])) or (from_port == 3389 and (ip_range == [{'CidrIp':'0.0.0.0/0'}] or ipv6 == [{'CidrIpv6': '::/0'}])):
                        ec2_client.revoke_security_group_ingress(
                            GroupId=group_id,
                            IpPermissions=[{
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpProtocol': 'tcp',
                                'IpRanges': ip_range,
                                'Ipv6Ranges': ipv6
                                }]
                            )
                    else:
                        pass
    except KeyError:
        print('Completed')
