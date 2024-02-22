#!/usr/bin/env python3
# -----------------------------------------------------------
#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: MIT-0
# This code demonstrates how to use a custom lambda function to attach secondary interfaces 
# on the AWS EKS worker using static/DHCP ip allocation method for EKS MULTUS nodegroup
# author: Raghvendra Singh
# -----------------------------------------------------------
import boto3
import botocore
import os,sys
import ipaddress
import time

from datetime import datetime

ec2_client = boto3.client('ec2')
asg_client = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
maxFreeIPCOUNT=15
startIndex=3
DELAY_SEC=2
instance_id=None

def lambda_handler(event, context):
    subnetDetails ={}
    tagsArr=[]
    instance_id = event['detail']['EC2InstanceId']
    LifecycleHookName=event['detail']['LifecycleHookName']
    AutoScalingGroupName=event['detail']['AutoScalingGroupName']
    useStaticIPs=False
    log("instance_id:"+str(instance_id) + " ASG:" + str(AutoScalingGroupName) + " LifecycleHookName" + str(LifecycleHookName) )   
    ##Fetch the comma separated security group list for the multus interfaces
    if os.environ['SecGroupIds'] :
        secgroup_ids = os.environ['SecGroupIds'].split(",")
    else:
        log("Empty Environment variable SecGroupIds:"+ os.environ['SecGroupIds'])
        exit (1)  
    ##Fetch the comma separated subnet list for the multus interfaces, The order in the subnet list provided that would be the order of the device-index on the instance   
    if os.environ['SubnetIds'] :
        subnet_ids = os.environ['SubnetIds'].split(",")
    else:
        log("Empty Environment variable SubnetIds:"+ os.environ['SubnetIds'])
        exit (1)   
    ##Check the flag, if the ENI needs to be created statically from the begining of the subnet or the IP allocation can happen dynamically    
    if 'useStaticIPs' in os.environ.keys():
        if os.environ['useStaticIPs']=="true":
            useStaticIPs=True
    ##Check if there are any tags need to be provisioned on the interfaces        
    if 'ENITags' in os.environ.keys():
        tagsArr = os.environ['ENITags'].split(",")

    ## Add tag for 'node.k8s.amazonaws.com/no_manage' = true
    tagsArr.append("node.k8s.amazonaws.com/no_manage=true")    
    tags=prepare_tags(tagsArr)   

    log("subnet-ids:"+str(subnet_ids)+ "  secgroup-ids:" + str(secgroup_ids) + " useStaticIPs:" + str(useStaticIPs))
    ##if only 1 securitygroupId is passed then use the same secgroup for all the secondary interfaces, i.e. same secgroup for all the subnet interfaces.
    if len(secgroup_ids) != len(subnet_ids):
        if len(secgroup_ids) == 1:
            index=1
            while index < len(subnet_ids) :
                secgroup_ids.append(secgroup_ids[0])
                index = index +1
        else:
            log("length of SecGroupIds :"+ len(secgroup_ids)  + "  not same as length of subnets "+ len(subnet_ids) )
            exit (1)               

    if event["detail-type"] == "EC2 Instance-launch Lifecycle Action":
        index = 1
        ##iterate over the subnet list in order it is sent, create and attach ENIs  on the worker node in same order (i.e. firsat subnet as device-index 1 and nth subnet as device-index n)
        for x in subnet_ids:
            subnetDetails.clear()
            interface_id=None
            attachment=None
            try: 
                ##Check whether the subnet is also an ipv6 subnet
                isIPv6=getsubnetData(x,subnetDetails)
                if useStaticIPs == False:
                    interface_id = create_interface(x,secgroup_ids[index-1],isIPv6,tags)
                ##  if the flag for creating the secondary ENI statically is set, then create the ENI statically else use DHCP to allocate the IP                  
                else:
                    ## Get the list of free IPs from the begining of the subnet cidr in subnetDetails dictionary
                    getFreeIPs(x,isIPv6,subnetDetails)  
                    interface_id = create_interface_static(x,secgroup_ids[index-1],isIPv6,subnetDetails,tags)
                ## if interface ENI  is successfully created then attach the ENI to instance  
                if interface_id:
                    time.sleep(DELAY_SEC)     ## sleep to get the resources created above to be available
                    attachment = attach_interface(interface_id,instance_id,index)
                index = index+1
            except Exception as e:
                log("Caught unexpected exception: " + str(e))
            ## if the interface Creation for the attachment to the instace failed, then invoke the Lifecycle failure event for the worker, as this worker couldnt be used    
            if not interface_id:
                complete_lifecycle_action_failure(LifecycleHookName,AutoScalingGroupName,instance_id)
                return
            elif not attachment:
                ## if the ENI was created but the attachment failed, due to some reason, then delete the ENI/interface as well
                complete_lifecycle_action_failure(LifecycleHookName,AutoScalingGroupName,instance_id)
                time.sleep(DELAY_SEC)
                delete_interface(interface_id)               
                return 
        complete_lifecycle_action_success(LifecycleHookName,AutoScalingGroupName,instance_id)

    if event["detail-type"] == "EC2 Instance-terminate Lifecycle Action":
        interface_ids = []
        attachment_ids = []

        # -* K8s draining function should be added here -*#

        complete_lifecycle_action_success(LifecycleHookName,AutoScalingGroupName,instance_id)


## This function reads the subnetdetails and stores the information like , subnet ipv4 & ipv6 cidr block. Function also retruns if the subnet is ipv6 or not
def getsubnetData(subnet_id,subnetDetails):
    ipv6=False
    try:
        response = ec2_client.describe_subnets(
            SubnetIds=[
                subnet_id,
            ],    
        )
        for i in response['Subnets']:
            subnetDetails['ipv4Cidr']=i['CidrBlock']
            if 'Ipv6CidrBlockAssociationSet' in i.keys():
                for j in  i['Ipv6CidrBlockAssociationSet']:
                    ipv6=True   
                    subnetDetails['ipv6Cidr']=j['Ipv6CidrBlock']
                    log("associated ipv6 CIDR: " + j['Ipv6CidrBlock'])
            if 'Tags' in i.keys():
                for j in i['Tags']:
                    if j['Key'] == "Name":
                        subnetDetails[j['Key']]=j['Value']

    except botocore.exceptions.ClientError as e:
        log("Error describing subnet : {}".format(e.response['Error']))
    return ipv6

## This function creates an ENI from the given subnet, security group, using DHCP IP allocation. 
## If the subnet is ipv6 subnet, then it also adds an ipv6 address to it
def create_interface(subnet_id,sg_id,isIPv6,tags):
    network_interface_id = None
    log("create_interface subnet:" + subnet_id +" secgroup:" + sg_id)
    if subnet_id:
        try:
            if isIPv6 == True:
                if tags:
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id,Ipv6AddressCount=1, TagSpecifications=[
                        {'ResourceType': 'network-interface', 'Tags': tags }]
                    )                                        
                else:
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id, Ipv6AddressCount=1)
            else :
                if tags:
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id,TagSpecifications=[
                        {'ResourceType': 'network-interface', 'Tags': tags }]
                    )                                        
                else:                
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id)
            network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
            log("Created network interface: {}".format(network_interface_id))
        except botocore.exceptions.ClientError as e:
            log("Error creating network interface: {}".format(e.response['Error']))
    return network_interface_id
## This function creates an ENI from the given subnet, security group, using static ips. subnetDetails is the dictionary provides the subnet freeIps 
## If the subnet is ipv6 subnet, then it also adds an ipv6 address to it
def create_interface_static(subnet_id,sg_id,isIPv6,subnetDetails,tags):
    network_interface_id = None
    log("create_interface_static subnet:" + subnet_id +" secgroup:" + sg_id)
    if subnet_id:
        ## Iterate over the unused IPs of the subnet, from the begining of the CIDR. if the interface creation fails then try to create with next ip, else break.
        for ip in subnetDetails['freeIpv4s']:
            try:
                if tags:
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id,PrivateIpAddress=ip, TagSpecifications=[
                        {'ResourceType': 'network-interface',
                        'Tags': tags }]
                        )                    
                else:     
                    network_interface = ec2_client.create_network_interface(Groups=[sg_id],SubnetId=subnet_id,PrivateIpAddress=ip)
                network_interface_id = network_interface['NetworkInterface']['NetworkInterfaceId']
                log("Created network interface:  "+ network_interface_id + " ipv4 IP: "+ ip )
                break                
            except botocore.exceptions.ClientError as e:
                log("Error creating network interface with ip: " + ip + " Error:" + str(e.response['Error'])+ " will try next free IP.")
        if isIPv6 == True :
            if network_interface_id == None:
                pass
            else:    
                if 'freeIpv6s' in subnetDetails.keys():
                    for ip in subnetDetails['freeIpv6s']:
                        try:
                            time.sleep(DELAY_SEC)     ## sleep to get the resources created above to be available
                            resp = ec2_client.assign_ipv6_addresses(Ipv6Addresses=[ip],NetworkInterfaceId=network_interface_id)
                            log("Assigned Ipv6 Address on ENI: "+ network_interface_id + " with ipv6 IP: "+ ip )
                            break
                        except botocore.exceptions.ClientError as e:
                             log("Error creating network interface with ip: " + ip + " Error:" + str(e.response['Error']) + " will try next free IP.")
    return network_interface_id

## This function first puts the node.k8s.amazonaws.com/no_manage tag then it attaches the ENI to the instance.
## It also disbale the source/destination check flag for multus based interfaces, as sometime these apps, might use non-vpc ips.
## It also sets the flag DeleteOnTermination on the ENI, so when the instance are terminated, ENI gets deleted as well and not left orphaned. 

def attach_interface(network_interface_id, instance_id, index):
    attachment = None
    log("attach_interface instance:" + instance_id +" eni:" + network_interface_id + " eni-index: " + str(index))

    if network_interface_id and instance_id:        
        try:
            attach_interface = ec2_client.attach_network_interface(
                NetworkInterfaceId=network_interface_id,
                InstanceId=instance_id,
                DeviceIndex=index
            )
            if 'AttachmentId' in attach_interface.keys():
                attachment = attach_interface['AttachmentId']
                log("Created network attachment: {}".format(attachment))
            else:
                 log("Network attachment creation returned NULLL")                  
        except botocore.exceptions.ClientError as e:
            log("Error attaching network interface: {}".format(e.response['Error']))
        try:
            network_interface = ec2.NetworkInterface(network_interface_id)
            #modify_attribute doesn't allow multiple parameter change at once..
            network_interface.modify_attribute(
                SourceDestCheck={
                    'Value': False
                }
            )
            network_interface.modify_attribute(
                Attachment={
                    'AttachmentId': attachment,
                    'DeleteOnTermination': True
                },
            )
        except botocore.exceptions.ClientError as e:
            log("Error modify_attribute network interface, will set attachment to None and fail the launch: {}".format(e.response['Error']))
            attachment = None

    return attachment
## This function adds tags on the interfaces, if there is a list provided by the CFN/CDK template
def prepare_tags(tagsArr):
    tags=[]
    for tag in tagsArr:
        x=tag.split('=')
        if len(x) > 1:
            tags.append({'Key': x[0],'Value': x[1]})
    return tags        

def add_tags(network_interface_id,tags,subnetDetails):
    network_interface = ec2.NetworkInterface(network_interface_id)
    if tags:
            network_interface.create_tags(
                Tags=tags
            ) 
## This function deletes the given interfaces, which is not attached to the worker node                                    
def delete_interface(network_interface_id):
    log("delete_interface eni:" + network_interface_id)

    try:
        ec2_client.delete_network_interface(
            NetworkInterfaceId=network_interface_id
        )
        log("Deleted network interface: {}".format(network_interface_id))
        return True

    except botocore.exceptions.ClientError as e:
        log("Error deleting interface {}: {}".format(network_interface_id,e.response['Error']))

## This function raises the event for successful completion of the lifecycle event for the EC2 for the given autoscaling group                                 
def complete_lifecycle_action_success(hookname,groupname,instance_id):
    try:
        asg_client.complete_lifecycle_action(
            LifecycleHookName=hookname,
            AutoScalingGroupName=groupname,
            InstanceId=instance_id,
            LifecycleActionResult='CONTINUE'
        )
        log("Lifecycle hook CONTINUEd for: {}".format(instance_id))
    except botocore.exceptions.ClientError as e:
            log("Error completing life cycle hook for instance {}: {}".format(instance_id, e.response['Error']))
            log('{"Error": "1"}')

## This function raises the event for failure of the lifecycle event for the EC2 for the given autoscaling group                                 
def complete_lifecycle_action_failure(hookname,groupname,instance_id):
    try:
        asg_client.complete_lifecycle_action(
            LifecycleHookName=hookname,
            AutoScalingGroupName=groupname,
            InstanceId=instance_id,
            LifecycleActionResult='ABANDON'
        )
        log("Lifecycle hook ABANDONed for: {}".format(instance_id))
    except botocore.exceptions.ClientError as e:
            log("Error completing life cycle hook for instance {}: {}".format(instance_id, e.response['Error']))
            log('{"Error": "1"}')

## This function gets the list of used IP address from the network interfaces a given subnet and stores it in list in the subnetDetails dictionary                             
def get_used_ip_list(subnet_id,subnetDetails):
    usedIpv4s=[]
    usedIpv6s=[]
    try:
        ## fetch all the ENIs created for the given subnetId
        resp = ec2_client.describe_network_interfaces(
                     Filters=[ {'Name': 'subnet-id',  'Values': [subnet_id] } ]
            ) 
        for en in resp['NetworkInterfaces']: 
            eni = en['NetworkInterfaceId'] 
            ## store the IPs on the ENI as used IP address 
            for ip in en['PrivateIpAddresses'] : 
                usedIpv4s.append(ip['PrivateIpAddress'])
            for ip in en['Ipv6Addresses'] : 
                usedIpv6s.append(ip['Ipv6Address'])
    except botocore.exceptions.ClientError as e:
        log("Error describing subnet : {}".format(e.response['Error']))  
    subnetDetails['usedIpv4s'] = usedIpv4s
    log("usedIpv4s: " + str(subnetDetails['usedIpv4s']))

    if len(usedIpv6s) >0 : 
        subnetDetails["usedIpv6s"]=usedIpv6s
        log("usedIpv6s: " + str(subnetDetails['usedIpv6s']))

## This function gets the list of unused IP address for the given subnet and stores it in list in the subnetDetails dictionary 
## Function iterates over the possible ip addresses, and if that IP is not used by any other ENI, then it stores it as free IP   
## To avoid unnecessary iterations , only maxFreeIPCOUNT (15) unused Ips are taken                          
def getFreeIPs(subnet_id,isIPv6, subnetDetails):
    get_used_ip_list(subnet_id,subnetDetails)
    net = ipaddress.IPv4Network(subnetDetails['ipv4Cidr'])
    subnetDetails['freeIpv4s']=[]
    subnetDetails['freeIpv6s']=[]

    count = 0
    for ip in net.hosts():
        count = count +1
        ipFree=False
        ##as first 4 Ips of a subnet are reserved by AWS, so start with the 4th ip of the subnet
        if count <= startIndex:
            continue 
        ## if the Ip is not in the used list then mark it free/unused    
        if  'usedIpv4s' in subnetDetails.keys():  
            if str(ip) not in subnetDetails['usedIpv4s']:
                ipFree = True
        else:
            ipFree= True
        if ipFree == True:          
            subnetDetails['freeIpv4s'].append(str(ip))
        if len (subnetDetails['freeIpv4s']) >= maxFreeIPCOUNT:
            log("Free Ips: " + str(subnetDetails['freeIpv4s']))
            break
    if isIPv6== True:   
        if 'ipv6Cidr' in subnetDetails.keys():
            net = ipaddress.IPv6Network(subnetDetails['ipv6Cidr'])
            count = 0         
            for ip in net.hosts():
                ipFree=False
                count = count +1
                if count <= startIndex:
                    continue 
                if  'usedIpv6s' in subnetDetails.keys():  
                    if str(ip) not in subnetDetails['usedIpv6s']:
                        ipFree = True
                else:
                    ipFree= True
                if ipFree == True:          
                    subnetDetails['freeIpv6s'].append(str(ip))
                if len (subnetDetails['freeIpv6s']) >= maxFreeIPCOUNT:
                    log("Free Ips: " + str(subnetDetails['freeIpv6s']))
                    break
def log(error):
    print('{}Z {}'.format(datetime.utcnow().isoformat(), error))

