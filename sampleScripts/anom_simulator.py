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

#>> args to run: python3 anom_simulator.py --msg-size 2000 --count 5000 --sleep-time 0.25 --thing-name anom_thing_1 --group-name anom_group --policy allow_iot_operations --security-profile-name ML_Detect_profile --region eu-west-1 --account_id <account-id> aws_profile <aws-profile-name>



import os.path
import sys
import threading
import time
from uuid import uuid4
import json
import argparse
import boto3
from awscrt import io, mqtt
from awsiot import mqtt_connection_builder

RECEIVED_COUNT = 0


# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("Connection interrupted. error: {}".format(error))


# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print(
        "Connection resumed. return_code: {} session_present: {}".format(
            return_code, session_present
        )
    )

    if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
        print("Session did not persist. Resubscribing to existing topics...")
        resubscribe_future, _ = connection.resubscribe_existing_topics()

        # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
        # evaluate result with a callback instead.
        resubscribe_future.add_done_callback(on_resubscribe_complete)
    if time.time() - start >= args.exitafter:
        print(f"Terminating process since {args.exitafter} seconds have elapsed")
        sys.exit(1)


def on_resubscribe_complete(resubscribe_future):
    resubscribe_results = resubscribe_future.result()
    print("Resubscribe results: {}".format(resubscribe_results))

    for topic, qos in resubscribe_results["topics"]:
        if qos is None:
            sys.exit("Server rejected resubscribe to topic: {}".format(topic))
    if time.time() - start >= args.exitafter:
        print(f"Terminating process since {args.exitafter} seconds have elapsed")
        sys.exit(1)


# Callback when the subscribed topic receives a message
def on_message_received(topic, payload, **kwargs):
    global RECEIVED_COUNT

    print("Received message from topic '{}': {}".format(topic, len(payload)))
    RECEIVED_COUNT += 1
    if RECEIVED_COUNT == args.count:
        received_all_event.set()
    if time.time() - start >= args.exitafter:
        print(f"Terminating process since {args.exitafter} seconds have elapsed")
        sys.exit(1)


def setup(
    region,
    account_id,
    thing_name,
    policy_name,
    group_name,
    security_profile_name,
    aws_profile=None,
):
    if aws_profile:
        session = boto3.Session(profile_name=aws_profile)
        client = session.client("iot", region_name=region)
    else:
        client = boto3.client("iot", region_name=region)
    thing = client.create_thing(thingName=thing_name)
    print(f"Thing creation of {thing_name} complete!")
    endpoint = client.describe_endpoint(endpointType="iot:Data-ATS")
    endpoint_address = endpoint["endpointAddress"]
    print(f"Found endpoint: {endpoint_address}")

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iot:Publish", "iot:Receive"],
                "Resource": [f"arn:aws:iot:{region}:{account_id}:topic/test/topic"],
            },
            {
                "Effect": "Allow",
                "Action": ["iot:Subscribe"],
                "Resource": [
                    f"arn:aws:iot:{region}:{account_id}:topicfilter/test/topic"
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["iot:Connect"],
                "Resource": [f"arn:aws:iot:{region}:{account_id}:client/*"],
            },
            {
                "Effect": "Deny",
                "Action": ["iot:Connect"],
                "Resource": [f"arn:aws:iot:{region}:{account_id}:client/baddevice"],
            },
        ],
    }
    policy_json = json.dumps(policy_doc)
    try:
        policy = client.create_policy(
            policyName=policy_name, policyDocument=policy_json
        )
        print(f"Created policy {policy_name}")
        # res_policy = client.list_policies()
    except client.exceptions.ResourceAlreadyExistsException:
        print(f"Policy {policy_name} already exists.")

    try:
        thing_group = client.create_thing_group(thingGroupName=group_name)
        client.attach_security_profile(
            securityProfileName=security_profile_name,
            securityProfileTargetArn=thing_group["thingGroupArn"],
        )
        client.attach_policy(
            policyName=policy_name, target=thing_group["thingGroupArn"]
        )

    except client.exceptions.ResourceAlreadyExistsException:
        print(f"Group {group_name} already exists.")
    # res_thing_group = client.list_thing_groups()

    client.add_thing_to_thing_group(thingGroupName=group_name, thingName=thing_name)

    cert = client.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]

    cert_id = cert["certificateId"]
    print(cert_id)
    with open("CLEANUP_cert.txt", "w") as f:
        f.write(f"Certificate: {cert_id}\n")
    client.attach_policy(policyName=policy_name, target=cert_arn)
    # res_cert = client.list_principal_policies(principal=cert_arn)

    return {
        "endpoint": endpoint_address,
        "priv": cert["keyPair"]["PrivateKey"],
        "cert": cert["certificatePem"],
        "thing_name": thing_name,
        "cert_arn": cert_arn,
        "thing_group": group_name,
        "cert_id": cert_id,
    }


def main(rand_str):

    print(f"ID {rand_str}")
    # Spin up resources
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)
    print(f"Launching setup of profiles....")
    setup_details = setup(
        args.region,
        args.account_id,
        args.thing_name,
        args.policy_name,
        args.group_name,
        args.security_profile_name,
        args.aws_profile,
    )

    mqtt_connection = mqtt_connection_builder.mtls_from_bytes(
        endpoint=setup_details["endpoint"],
        cert_bytes=setup_details["cert"].encode("utf-8"),
        pri_key_bytes=setup_details["priv"].encode("utf-8"),
        client_bootstrap=client_bootstrap,
        ca_filepath="./AmazonRootCA1.pem",
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed,
        client_id=setup_details["thing_name"],
        clean_session=False,
        keep_alive_secs=6,
    )

    print(
        "Connecting to {} with client ID '{}'...".format(
            setup_details["endpoint"], setup_details["thing_name"]
        )
    )

    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected!")
    topic = "test/topic"
    message = "A" * args.msg_size
    print("Subscribing to topic '{}'...".format(topic))
    subscribe_future, packet_id = mqtt_connection.subscribe(
        topic=topic, qos=mqtt.QoS.AT_LEAST_ONCE, callback=on_message_received
    )

    subscribe_result = subscribe_future.result()
    print("Subscribed with {}".format(str(subscribe_result["qos"])))
    if args.count == 0:
        print("Sending messages until program killed")
    else:
        print("Sending {} message(s)".format(args.count))
    publish_count = 1
    while publish_count <= args.count:
        print(
            f"Publishing message [{publish_count}/{args.count}] to topic '{topic}': {len(message)}"
        )

        mqtt_connection.publish(
            topic=topic, payload=message, qos=mqtt.QoS.AT_LEAST_ONCE
        )
        print(f"Sleeping for {args.sleep_time} seconds")
        time.sleep(args.sleep_time)
        publish_count += 1
        if time.time() - start >= args.exitafter:
            print(f"Terminating process since {args.exitafter} seconds have elapsed")
            sys.exit(1)
    # Wait for all messages to be received.
    # This waits forever if count was set to 0.
    if args.count != 0 and not received_all_event.is_set():
        print("Waiting for all messages to be received...")
    received_all_event.wait()
    print("{} message(s) received.".format(received_count))

    # Disconnect
    print("Disconnecting...")
    disconnect_future = mqtt_connection.disconnect()
    disconnect_future.result()
    print("Disconnected!")


if __name__ == "__main__":
    if not os.path.isfile("AmazonRootCA1.pem"):
        print(
            "Cannot find CA cert. Please download from: https://www.amazontrust.com/repository/AmazonRootCA1.pem"
        )
        sys.exit(1)
    rand_str = str(uuid4())
    start = time.time()
    parser = argparse.ArgumentParser(
        description="Send and receive messages through an MQTT connection."
    )
    parser.add_argument("--aws_profile", help="AWS profile name")
    parser.add_argument("--region", required=True, help="prefered AWS region")
    parser.add_argument("--account_id", required=True, help="AWS account number")
    parser.add_argument(
        "--count",
        default=10,
        type=int,
        help="Number of messages to publish/receive before exiting.",
    )
    parser.add_argument(
        "--thing-name", default=f"my-thing-{rand_str}", help="Thing Name for device"
    )
    parser.add_argument(
        "--group-name", default=f"my-group-name-{rand_str}", help="ThingGroup Name"
    )
    parser.add_argument(
        "--policy-name", default=f"my-policy-{rand_str}", help="IoT Policy Name"
    )
    parser.add_argument(
        "--security-profile-name",
        required=True,
        help="Security Profile name to attach the thing group to (the one with ML-detect enabled.)",
    )
    parser.add_argument(
        "--msg-size", type=int, default=20000, help="Size of message in bytes"
    )
    parser.add_argument(
        "--sleep-time", type=float, default=1.0, help="Interval between each message"
    )
    parser.add_argument(
        "--exitafter", type=int, default=30 * 60, help="Exit process after X seconds"
    )
    args = parser.parse_args()

    received_count = 0
    received_all_event = threading.Event()

    main(rand_str)
