import boto3

ssm = boto3.client('ssm', region_name='us-east-1')
ec2 = boto3.client('ec2', region_name='us-east-1')

params = {
    'al2023': '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
    'ubuntu24': '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id',
    'win2022': '/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base'
}

found = {}
for name, p in params.items():
    try:
        res = ssm.get_parameter(Name=p)
        val = res['Parameter']['Value']
        found[name] = val
        print(f'{name}: {val}')
    except Exception as e:
        print(f'{name} err: {e}')

# Busca Debian 12 oficial da AWS Marketplace / Debian
deb_res = ec2.describe_images(
    Owners=['136693071363'],  # Debian Official
    Filters=[
        {'Name': 'name', 'Values': ['debian-12-amd64-*']},
        {'Name': 'state', 'Values': ['available']}
    ]
)
if deb_res['Images']:
    sorted_deb = sorted(deb_res['Images'], key=lambda x: x['CreationDate'], reverse=True)
    found['debian12'] = sorted_deb[0]['ImageId']
    print(f'debian12: {found["debian12"]}')

# Busca RHEL 9 oficial da Red Hat
rhel_res = ec2.describe_images(
    Owners=['309956199498'],  # Red Hat Official
    Filters=[
        {'Name': 'name', 'Values': ['RHEL-9.*_HVM-*-x86_64-*']},
        {'Name': 'state', 'Values': ['available']}
    ]
)
if rhel_res['Images']:
    sorted_rhel = sorted(rhel_res['Images'], key=lambda x: x['CreationDate'], reverse=True)
    found['rhel9'] = sorted_rhel[0]['ImageId']
    print(f'rhel9: {found["rhel9"]}')
