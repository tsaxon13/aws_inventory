import boto3
import xlsxwriter

"""
Get inventory of AWS resources and create a spreadsheet with the data
Author: Tony Saxon

Usage: python3 inventory.py

Usefule code snippets:
   
    # Create a list of S3 buckets.
    s3_buckets = [get_s3_buckets(session) for session in sessions]

    # Create a list of EC2 instances in current region.
    ec2_instances = [get_ec2_instances(session) for session in sessions]

    # Gets a list of all ec2 instances in all selected profiles 
    ec2_instance_list = []
    for instances_in_profile in [ec2_instances_list(session) for session in sessions]:
        for instance in instances_in_profile:
            ec2_instance_list.append(instance)

    # Create a list of AutoScaling groups.
    asg = [get_asg(session) for session in sessions]
    # asg name: asg[0]['AutoScalingGroups'][0]['AutoScalingGroupName']

    # Create a list of all the resources.
    resources = [s3_buckets, asg]
""" 

def get_available_region_list(session):
    """
    Get a list of regions available for the session.
    """
    ec2 = session.client('ec2')
    regions = []
    for region in ec2.describe_regions()['Regions']:
        regions.append(region['RegionName'])
    return regions

def get_s3_buckets(session):
    """
    Get a list of S3 buckets based on the session provided.
    """
    print("processing s3 buckets for " + session.profile_name + "...")
    s3 = session.client('s3')
    return s3.list_buckets()

def get_asg(session, region):
    """
    Get a list of AutoScaling groups based on the session and region provided.
    """
    print("processing asg for " + session.profile_name + "/" + region + "...")
    asgs = []

    asg = session.client('autoscaling', region_name=region)
    try:
        for asg in asg.describe_auto_scaling_groups()['AutoScalingGroups']:
            asgs.append(asg['AutoScalingGroupName'])
    except:
        pass

    return asgs

def get_ec2_instances(session, region):
    """
    Get a list of EC2 instances based on the session and region provided.
    """
    print("processing ec2 instances for " + session.profile_name + "/" + region + "...")
    instances = []
    
    ec2 = session.resource('ec2', region_name=region)
    try:
        for instance in ec2.instances.all():
            instances.append(instance)
    except:
        pass

    return instances

def get_security_groups(session, region):
    """
    Get a list of security groups based on the session and region provided.
    """
    print("processing security groups for " + session.profile_name + "/" + region + "...")
    security_groups = []
    try:
        ec2 = session.resource('ec2', region_name=region)
        for security_group in ec2.security_groups.all():
            security_groups.append(security_group)
        return security_groups
    except:
        return []

def get_profile_list():
    """
    Get list of AWS profiles.
    """
    return boto3.session.Session().available_profiles

def set_profile_list():
    """
    Set the list of AWS profiles to use.
    """
    all_profiles = get_profile_list()

    import inquirer
    questions = [inquirer.Checkbox('profiles',message="Select profiles to use", choices=all_profiles),]
    answers = inquirer.prompt(questions)
    return answers

def s3_buckets_list(session):
    """
    return list of S3 buckets.
    """
    s3_buckets = get_s3_buckets(session)
    buckets = []
    for bucket in s3_buckets["Buckets"]:
        # get bucket location
        try:
            location = session.client('s3').get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
        except:
            location = "Error getting bucket location for bucket: {}".format(bucket['Name'])
        buckets.append([bucket["Name"], session.profile_name, location])
    return buckets

def asg_list(session):
    """
    Return a list of AutoScaling groups.
    """
    regions = get_available_region_list(session)
    asgs = []
    for region in regions:
        asg_list = get_asg(session, region)
        for asg in asg_list:
            asgs.append([asg, session.profile_name, region])
    return asgs

def ec2_instances_list(session):
    """
    Return the EC2 instances in list format.
    """
    regions = get_available_region_list(session)
    instances = []
    for region in regions:
        ec2_instances = get_ec2_instances(session, region)
        
        for instance in ec2_instances:
            security_groups = ""
            name = ""
            instance_id = instance.id
            vpc_id = instance.vpc_id
            security_groups_raw = instance.security_groups
            for group in security_groups_raw:
                security_groups += group['GroupId'] + ", "
            security_groups = security_groups[:-2]
            if instance.tags != None:
                for tag in instance.tags:
                    if tag['Key'] != 'Name':
                        continue
                    else:
                        name = tag['Value']
            instance_state = instance.state['Name']
            instances.append([instance_id, name, instance_state, session.profile_name, region, security_groups, vpc_id])
    return instances

def vpc_list(session):
    """
    Return the VPCs in list format.
    """
    regions = get_available_region_list(session)
    vpcs = []
    for region in regions:
        try:
            ec2 = session.resource('ec2', region_name=region)
            for vpc in ec2.vpcs.all():
                vpc_id = vpc.id
                vpc_cidr = vpc.cidr_block
                vpc_is_default = vpc.is_default
                vpcs.append([vpc_id, session.profile_name, region, vpc_cidr, vpc_is_default])
        except:
            print("Error getting VPCs for region: {}".format(region))
    return vpcs

def subnet_list(session):
    """
    Return the subnets in list format.
    """
    regions = get_available_region_list(session)
    subnets = []
    for region in regions:
        try:
            ec2 = session.resource('ec2', region_name=region)
            for subnet in ec2.subnets.all():
                subnet_id = subnet.id
                subnet_name = ""
                if subnet.tags != None:
                    for tag in subnet.tags:
                        if tag['Key'] != 'Name':
                            continue
                        else:
                            subnet_name = tag['Value']
                subnet_cidr = subnet.cidr_block
                subnet_vpc_id = subnet.vpc_id
                subnet_availability_zone = subnet.availability_zone
                subnets.append([subnet_id, subnet_name, session.profile_name, region, subnet_vpc_id, subnet_cidr, subnet_availability_zone])
        except Exception as e:
            print("Error getting subnets for region: {}".format(region) + ": " + str(e))
    return subnets

def security_groups_list(session):
    """
    Return the security groups in list format.
    """
    regions = get_available_region_list(session)
    security_groups = []
    for region in regions:
        security_groups_list = get_security_groups(session, region)
        for security_group in security_groups_list:
            group_name = security_group.group_name
            group_id = security_group.id
            vpc_id = security_group.vpc_id
            group_description = security_group.description
            # process ingress rules
            for rule in security_group.ip_permissions:
                port = ""
                endpoint = ""
                protocol = rule['IpProtocol']

                if protocol != "-1":
                    port = rule['FromPort']
                else:
                    port = "All"

                if rule['IpRanges'] != []:
                    for ip_range in rule['IpRanges']:
                        endpoint = ip_range['CidrIp']
                        if 'Description' in ip_range.keys():
                            rule_description = ip_range['Description']
                        else:
                            rule_description = "None"
                        security_groups.append([group_name, group_id, vpc_id, group_description, session.profile_name, region, "inbound", port, endpoint, rule_description])

                if rule['UserIdGroupPairs'] != []:
                    for user_group in rule['UserIdGroupPairs']:
                        try:
                            sg_name = session.client('ec2').describe_security_groups(GroupIds=[user_group['GroupId']])['SecurityGroups'][0]['GroupName']
                        except:
                            sg_name = "Unknown Name"

                        try:
                            endpoint_description = session.client('ec2').describe_security_groups(GroupIds=[user_group['GroupId']])['SecurityGroups'][0]['Description']
                        except:
                            endpoint_description = "Unknown Description"

                        endpoint = user_group['GroupId'] + "/" + sg_name + "/" + endpoint_description
                        rule_description = "None"
                        security_groups.append([group_name, group_id, vpc_id, group_description, session.profile_name, region, "inbound", port, endpoint, rule_description])

            # process egress rules
            for rule in security_group.ip_permissions_egress:
                port = ""
                endpoint = ""
                protocol = rule['IpProtocol']

                if protocol != "-1":
                    port = rule['FromPort']
                else:
                    port = "All"

                if rule['IpRanges'] != []:
                    for ip_range in rule['IpRanges']:
                        endpoint = ip_range['CidrIp']
                        if 'Description' in ip_range.keys():
                            rule_description = ip_range['Description']
                        else:
                            rule_description = "None"
                        security_groups.append([group_name, group_id, vpc_id, group_description, session.profile_name, region, "outbound", port, endpoint, rule_description])

                if rule['UserIdGroupPairs'] != []:
                    for user_group in rule['UserIdGroupPairs']:
                        try:
                            sg_name = session.client('ec2').describe_security_groups(GroupIds=[user_group['GroupId']])['SecurityGroups'][0]['GroupName']
                        except:
                            sg_name = "Unknown Name"
                        
                        try:
                            endpoint_description = session.client('ec2').describe_security_groups(GroupIds=[user_group['GroupId']])['SecurityGroups'][0]['Description']
                        except:
                            endpoint_description = "Unknown Description"

                        endpoint = user_group['GroupId'] + "/" + sg_name + "/" + endpoint_description
                        rule_description = "None"
                        security_groups.append([group_name, group_id, vpc_id, group_description, session.profile_name, region, "outbound", port, endpoint, rule_description])

    return security_groups

def write_worksheet(workbook, worksheet_name, data):
    """
    Write data to the worksheet.
    """
    worksheet = workbook.add_worksheet(worksheet_name)

    for row_num, row_data in enumerate(data):
        for col_num, cell_data in enumerate(row_data):
            worksheet.write(row_num, col_num, cell_data)
    
def init():
    """
    Initialize logic.
    """
    # Set global variables
    global profiles, sessions, s3_buckets, asg, ec2_instances, workbook_file
    # Set the list of profiles to use.
    profiles = set_profile_list()['profiles']
    # get a file to write data to
    workbook_file = input("Enter a file name to write data to ('aws_inventory.xlsx'): ") or "aws_inventory.xlsx"
    # Create a list of boto3 sessions.
    sessions = [boto3.session.Session(profile_name=profile) for profile in profiles]

def main():
    init()
    # Open workbook
    workbook = xlsxwriter.Workbook(workbook_file)
    # Create a list of S3 buckets.
    s3_buckets = [s3_buckets_list(session) for session in sessions]
    s3_buckets_flat = [item for sublist in s3_buckets for item in sublist]
    s3_buckets_flat.insert(0,["Bucket Name", "Profile", "LocationConstraint"])
    # Write S3 buckets to spreadsheet.
    write_worksheet(workbook, "S3 Buckets", s3_buckets_flat)
    # Create a list of EC2 instances.
    ec2_instances = [ec2_instances_list(session) for session in sessions]
    ec2_instances_flat = [item for sublist in ec2_instances for item in sublist]
    ec2_instances_flat.insert(0,["Instance ID", "Name", "Instance State", "Profile", "Region", "Security Groups", "VPC ID"])
    # Write EC2 instances to spreadsheet.
    write_worksheet(workbook, "EC2 Instances", ec2_instances_flat)
    # Create a list of Security Group rules.
    security_groups = [security_groups_list(session) for session in sessions]
    security_groups_flat = [item for sublist in security_groups for item in sublist]
    security_groups_flat.insert(0,["Group Name", "Group ID", "VPC ID", "Group Description", "Profile", "Region", "Direction", "Port", "Endpoint", "Rule Description"])
    # Write Security Group rules to spreadsheet.
    write_worksheet(workbook, "Security Group Rules", security_groups_flat)    
    # Create a list of AutoScaling groups.
    asg = [asg_list(session) for session in sessions]
    asg_flat = [item for sublist in asg for item in sublist]
    asg_flat.insert(0,["AutoScaling Group", "Profile", "Region"])
    # Create a list of VPCs.
    vpcs = [vpc_list(session) for session in sessions]
    vpcs_flat = [item for sublist in vpcs for item in sublist]
    vpcs_flat.insert(0,["VPC ID", "Profile", "Region", "CIDR Block", "Is Default"])
    # Create a list of Subnets.
    subnets = [subnet_list(session) for session in sessions]
    subnets_flat = [item for sublist in subnets for item in sublist]
    subnets_flat.insert(0,["Subnet ID", "Subnet Name", "Profile", "Region", "VPC ID", "CIDR Block", "Availability Zone"])
    # Create a list of IAM users. Comin' soon.

    # Write AutoScaling groups to spreadsheet.
    write_worksheet(workbook, "AutoScaling Groups", asg_flat)
    workbook.close()

if __name__ == "__main__":
    main()