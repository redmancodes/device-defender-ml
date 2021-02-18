MIT License

Copyright (c) 2020 Syed Rehan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


import os.path
import sys
import time
from uuid import uuid4
import json
import argparse
import boto3

from awscrt import io
from awsiot import mqtt_connection_builder

policy_doc = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["iot:Connect"], "Resource": ["*"]}],
}


def connect_me(endpoint, cert, client_bootstrap, thing_name):
    mqtt_connection = mqtt_connection_builder.mtls_from_bytes(
        endpoint=endpoint,
        cert_bytes=cert["certificatePem"].encode("utf-8"),
        pri_key_bytes=cert["keyPair"]["PrivateKey"].encode("utf-8"),
        client_bootstrap=client_bootstrap,
        ca_filepath="./AmazonRootCA1.pem",
        client_id=thing_name,
        keep_alive_secs=5,
    )

    print("Connecting to {} with client ID '{}'...".format(endpoint, thing_name))
    connect_future = mqtt_connection.connect()
    # print(connect_future)
    connect_future.result()
    # print(connect_future)

    print(f"Connected! using {thing_name}")
    return mqtt_connection


def main(endpoint, region_name, aws_profile=None):
    rand_str = str(uuid4())
    print(rand_str)
    if aws_profile != "default":
        boto3.setup_default_session(profile_name=aws_profile)
    client = boto3.client("iot", region_name=region_name)
    cert = client.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    # print(cert_id)

    thing_name1 = f"thing_name1_{rand_str}"

    client.create_thing(thingName=thing_name1)
    client.attach_thing_principal(thingName=thing_name1, principal=cert_arn)

    thing_name2 = f"thing_name2_{rand_str}"
    client.create_thing(thingName=thing_name2)
    client.attach_thing_principal(thingName=thing_name2, principal=cert_arn)

    group_name = f"tmp_group_{rand_str}"
    thing_group = client.create_thing_group(thingGroupName=group_name)

    policy_json = json.dumps(policy_doc)
    policy_name = f"tmp_policy_{rand_str}"
    client.create_policy(policyName=policy_name, policyDocument=policy_json)
    client.attach_policy(policyName=policy_name, target=thing_group["thingGroupArn"])
    client.add_thing_to_thing_group(thingGroupName=group_name, thingName=thing_name1)
    client.add_thing_to_thing_group(thingGroupName=group_name, thingName=thing_name2)
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    connection_1 = connect_me(endpoint, cert, client_bootstrap, thing_name1)
    print(f"Connection 1: {connection_1}")
    connection_2 = connect_me(endpoint, cert, client_bootstrap, thing_name2)
    print(f"Connection 2: {connection_2}")
    with open("CLEANUP_cert.txt", "w") as f:
        f.write(f"Certificate: {cert_id}\n")
        f.write(f"ThingName: {thing_name1}\n")
        f.write(f"ThingName: {thing_name2}\n")
        f.write(f"Policy: {policy_name}\n")
        f.write(f"GroupNames: {group_name}\n")

    print("Sleeping for 10 seconds")
    time.sleep(10)


if __name__ == "__main__":
    if not os.path.isfile("AmazonRootCA1.pem"):
        print(
            "Cannot find CA cert. Please download from: https://www.amazontrust.com/repository/AmazonRootCA1.pem"
        )
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description="Create MQTT connection from two (simulated) devices with a shared certificate"
    )
    parser.add_argument("--aws_profile", help="AWS profile name")
    parser.add_argument(
        "--endpoint",
        required=True,
        help="AWS IoT endpoint for creating the MQTT connection",
    )
    parser.add_argument("--region", required=True, help="prefered AWS region")
    args = parser.parse_args()
    main(args.endpoint, args.region, args.aws_profile)
