import boto3
import json
from datetime import datetime, timezone

def audit_security_groups():
    ec2 = boto3.client('ec2')
    findings = []
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        for permission in sg.get('IpPermissions', []):
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    findings.append({
                        'Resource': sg['GroupId'],
                        'Issue': 'Security Group allows unrestricted access',
                        'Port': permission.get('FromPort'),
                        'Severity': 'High'
                    })
    return findings

def audit_iam_users():
    iam = boto3.client('iam')
    findings = []
    users = iam.list_users()['Users']
    for user in users:
        mfa = iam.list_mfa_devices(UserName=user['UserName'])
        if not mfa['MFADevices']:
            findings.append({
                'Resource': user['UserName'],
                'Issue': 'IAM user has no MFA',
                'Severity': 'High'
            })
    return findings

def audit_iam_policies():
    iam = boto3.client('iam')
    findings = []
    policies = iam.list_policies(Scope='Local')['Policies']
    for policy in policies:
        version = iam.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        doc = version['PolicyVersion']['Document']
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                findings.append({
                    'Resource': policy['PolicyName'],
                    'Issue': 'Overly permissive IAM policy',
                    'Severity': 'High'
                })
    return findings

def audit_s3_buckets():
    s3 = boto3.client('s3')
    findings = []
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append({
                        'Resource': name,
                        'Issue': 'S3 bucket is publicly accessible',
                        'Severity': 'High'
                    })
            enc = s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                findings.append({
                    'Resource': name,
                    'Issue': 'S3 bucket is not encrypted',
                    'Severity': 'Medium'
                })
    return findings

def audit_root_account():
    iam = boto3.client('iam')
    findings = []
    summary = iam.get_account_summary()['SummaryMap']
    if summary.get('AccountAccessKeysPresent', 0) > 0:
        findings.append({
            'Resource': 'Root Account',
            'Issue': 'Root account has access keys',
            'Severity': 'High'
        })
    return findings

def audit_cloudtrail():
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails()['trailList']
    findings = []
    if not trails:
        findings.append({
            'Resource': 'CloudTrail',
            'Issue': 'CloudTrail is not enabled',
            'Severity': 'High'
        })
    return findings

def audit_access_keys():
    iam = boto3.client('iam')
    findings = []
    users = iam.list_users()['Users']
    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for key in keys:
            last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
            if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                days_unused = (datetime.now(timezone.utc) - last_used['AccessKeyLastUsed']['LastUsedDate']).days
                if days_unused > 90:
                    findings.append({
                        'Resource': key['AccessKeyId'],
                        'Issue': f'Access key unused for {days_unused} days',
                        'Severity': 'Medium'
                    })
            else:
                findings.append({
                    'Resource': key['AccessKeyId'],
                    'Issue': 'Access key has never been used',
                    'Severity': 'Medium'
                })
    return findings

def run_audit():
    all_findings = []
    all_findings.extend(audit_security_groups())
    all_findings.extend(audit_iam_users())
    all_findings.extend(audit_iam_policies())
    all_findings.extend(audit_s3_buckets())
    all_findings.extend(audit_root_account())
    all_findings.extend(audit_cloudtrail())
    all_findings.extend(audit_access_keys())

    with open('aws_audit_report.json', 'w') as f:
        json.dump(all_findings, f, indent=4)
    print("Audit complete. Report saved to aws_audit_report.json")

if __name__ == "__main__":
    run_audit()
