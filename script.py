import boto3
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def launch_instance():
    instance_details = None
    error_message = None

    if request.method == 'POST':
        try:
            instance_type = request.form['instance_type']
            ami_id = request.form['ami_id']
            key_name = request.form['key_name']
            security_group = request.form['security_group']

            ec2 = boto3.resource('ec2')

            instances = ec2.create_instances(
                ImageId=ami_id,
                MinCount=1,
                MaxCount=1,
                InstanceType=instance_type,
                KeyName=key_name,
                SecurityGroupIds=[security_group]
            )

            instance = instances[0]
            instance.wait_until_running()
            instance.load()

            instance_details = {
                'InstanceId': instance.id,
                'InstanceType': instance.instance_type,
                'ImageId': instance.image_id,
                'KeyName': instance.key_name,
                'SecurityGroups': [sg['GroupId'] for sg in instance.security_groups],
                'State': instance.state['Name']
            }

        except Exception as e:
            error_message = str(e)

    return render_template('index.html', instance_details=instance_details, error_message=error_message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
