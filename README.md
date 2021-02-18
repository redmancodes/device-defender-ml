# AWS IoT Device Defender ML Detect
We will setup ML Detect feature using AWS CLI using following guide and will also setup scripts on how to create anamoly from device side for us to test the system.

Lets first setup our ML Detect Security profile and go through steps on attaching to specific IoT things (devices) / group.

## Step 1 Enable ML Detect on device group(s) 

### Using AWS CLI

Before we setup using AWS CLI, please make sure you have AWS CLI setup for your environment (setting up CLI for your environment [further instructions](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)) and configure correctly ([further instructions](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)). The minimum required version of the CLI for setting this up is is **at least 1.9.12 or higher** ****(including aws cli v2)

You can test AWS CLI to make sure its all setup correctly 


```
aws help 
```

Step 1 [name]
Once you have setup / updated your CLI to minimum required version, we will start by creating Security Profile using following snippet as below:

Create Security Profile command:


```
aws ml-iot create-security-profile \
    --security-profile-name <value> \
    [--security-profile-description <value>] \
    [--behaviors <value>] \
    [--alert-targets <value>] \
    [--additional-metrics-to-retain <value>] \
    [--tags <value>]  \
    [--cli-input-json <value>] \
    [--generate-cli-skeleton]
```

Sample using **eu-west-1** as region and Profile name **ML_Detect_profile**:


```
aws ml-iot create-security-profile \
    --security-profile-name ML_Detect_profile \
    --behaviors \
     '[{
      "name": "num-messages-sent-ml-behavior",
      "metric": "aws:num-messages-sent",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": true    
  },
  {
      "name": "num-authorization-failures-ml-behavior",
      "metric": "aws:num-authorization-failures",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": true                
  },
  {
      "name": "num-connection-attempts-ml-behavior",
      "metric": "aws:num-connection-attempts",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": true
  },
  {
      "name": "num-disconnects-ml-behavior",
      "metric": "aws:num-disconnects",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": true
  },
{
    "name": "num-msg-received-ml-behavior",
    "metric": "aws:num-messages-received",
    "criteria": {
        "mlDetectionConfig": {
            "confidenceLevel" : "MEDIUM"
        }
    },
    "suppressAlerts": true
},
{
    "name": "msg-byte-size-ml-behavior",
    "metric": "aws:message-byte-size",
    "criteria": {
        "mlDetectionConfig": {
            "confidenceLevel" : "MEDIUM"
        }
    },
    "suppressAlerts": true
}]' \
  --region eu-west-1 --endpoint-url https://iot.eu-west-1.amazonaws.com
```

## **Missing command attaching security profile to device groups **

## **Step 2 ML Model build status report**

### Using AWS CLI

We will use the get-behavior-model-training-summaries command to obtain the status of our model. Please update the region which you are using. Region details can be found [here](https://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region) and CLI to obtain detail on region [here](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-regions.html)

ML Model training summary command:


```
aws ml-iot get-behavior-model-training-summaries
          [--security-profile-name <value>]
          [--max-results <value>]
          [--next-token <value>]
          [--cli-input-json | --cli-input-yaml]
          [--generate-cli-skeleton <value>]
          [--cli-auto-prompt <value>]
```


Sample for **Ireland Region** i will run this as follows with profile name being **ML_Detect_profile**:

```
aws ml-iot get-behavior-model-training-summaries
-security-profile-name ML_Detect_profile 
--region eu-west-1 
--endpoint-url https://iot.eu-west-1.amazonaws.com/
```

we should see following output as below:
```
{
 "summaries": [
{
"securityProfileName": "ML_Detect_profile",
"behaviorName": "num-messages-sent-ml-behavior",
"behaviorCreateDate": 1600763457.948,
"modelStatus": "PENDING_BUILD",
"datapointsCollectionPercentage": 0.0
},

{
"securityProfileName": "ML_Detect_profile",
"behaviorName": "num-authorization-failures-ml-behavior",
"behaviorCreateDate": 1600763457.948,
"modelStatus": "PENDING_BUILD",
"datapointsCollectionPercentage": 0.0
},

{
"securityProfileName": "ML_Detect_profile",
"behaviorName": "num-connection-attempts-ml-behavior",
"behaviorCreateDate": 1600763457.948,
"modelStatus": "PENDING_BUILD",
"datapointsCollectionPercentage": 0.0
},

{
"securityProfileName": "ML_Detect_profile",
"behaviorName": "num-disconnects-ml-behavior",
"behaviorCreateDate": 1600763457.948,
"modelStatus": "PENDING_BUILD",
"datapointsCollectionPercentage": 0.0
}
]
}
```
Same as console we can see attribute modelStatus: being PENDING_BUILD, once it becomes active we will see the ACTIVE state.

## **3 Review your ML Detect alarms**

Let’s view Active violations using **list-active-violations** ****with further options i.e. max result being 2
*Please update the region which you are using. Region details can be found [here](https://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region) and CLI to obtain detail on region [here](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-regions.html)*

Command for Active violations:


```
aws ml-iot list-active-violations
          [--thing-name <value>]
          [--security-profile-name <value>]
          [--behavior-criteria-type <value>]
          [--list-suppressed-alerts | --no-list-suppressed-alerts]
          [--next-token <value>]
          [--max-results <value>]
          [--cli-input-json | --cli-input-yaml]
          [--generate-cli-skeleton <value>]
          [--cli-auto-prompt <value>]
```

Command for Violation Events:


```
aws ml-iot list-violation-events
          --start-time <value>
          --end-time <value>
          [--thing-name <value>]
          [--security-profile-name <value>]
          [--behavior-criteria-type <value>]
          [--list-suppressed-alerts | --no-list-suppressed-alerts]
          [--next-token <value>]
          [--max-results <value>]
          [--cli-input-json | --cli-input-yaml]
          [--generate-cli-skeleton <value>]
          [--cli-auto-prompt <value>]
```


Sample command for active violations for Ireland region:
```
aws ml-iot list-active-violations 
--max-results 2 
-—region eu-west-1
```

Sample command for active historical violation events with specific start time and end time i.e.

```
aws ml-iot list-violation-events \
--start-time 1599500533 --end-time 1600796533 \
--max-results 2 \
--region eu-west-1 
--endpoint-url https://iot.eu-west-1.amazonaws.com/
```

Sample output:


```
{
    "violationEvents": [
        {
            "violationId": "1448be98c09c3d4ab7cb9b6f3ece65d6",
            "thingName": "ddml12",
            "securityProfileName": "ML_Detect_profile",
            "behavior": {
                "name": "LowConfidence_MladBehavior_MessagesReceived",
                "metric": "aws:num-messages-received",
                "criteria": {
                    "mlDetectionConfig": {
                        "confidenceLevel": "LOW"
                    }
                },
                "suppressAlerts": false
            },
            "violationEventType": "alarm-cleared",
            "violationEventTime": 1600780245.29
        }
}
```

## **Step 4 Fine-tune your ML Detect notifications**

Similarly using CLI we can update Confidence level and not to suppress alerts using sample command as below (using EU Ireland as region):
*Please update the region which you are using. Region details can be found [here](https://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region) and CLI to obtain detail on region [here](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-regions.html)and update **Security Profile** name*

Command for updating Security profile:


```
aws ml-iot update-security-profile
--security-profile-name <value>
[—security-profile-description <value>]
[—behaviors <value>]
[—alert-targets <value>]
[—additional-metrics-to-retain <value>]
[—additional-metrics-to-retain-v2 <value>]
[--delete-behaviors | —no-delete-behaviors]
[--delete-alert-targets | —no-delete-alert-targets]
[--delete-additional-metrics-to-retain | —no-delete-additional-metrics-to-retain]
[—expected-version <value>]
[--cli-input-json | —cli-input-yaml]
[—generate-cli-skeleton <value>]
[—cli-auto-prompt <value>]
```

Sample Command for updating the security profile:


```
aws ml-iot update-security-profile \
    --security-profile-name ML_Detect_profile \
    --behaviors \
     '[{
      "name": "num-messages-sent-ml-behavior",
      "metric": "aws:num-messages-sent",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "HIGH"
          }
      },
      "suppressAlerts": false
  },
  {
      "name": "num-authorization-failures-ml-behavior",
      "metric": "aws:num-authorization-failures",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "HIGH"
          }
      },
      "suppressAlerts": false
  },
  {
      "name": "num-connection-attempts-ml-behavior",
      "metric": "aws:num-connection-attempts",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": false
  },
  {
      "name": "num-disconnects-ml-behavior",
      "metric": "aws:num-disconnects",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "LOW"
          }
      },
      "suppressAlerts": true
  },
  {
      "name": "num-msg-received-ml-behavior",
      "metric": "aws:num-messages-received",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "MEDIUM"
          }
      },
      "suppressAlerts": true
  },
  {
      "name": "msg-byte-size-ml-behavior",
      "metric": "aws:message-byte-size",
      "criteria": {
          "mlDetectionConfig": {
              "confidenceLevel" : "HIGH"
          }
      },
      "suppressAlerts": false
  }]' \
  --region eu-west-1 --endpoint-url https://iot.eu-west-1.amazonaws.com
```

## **Step 5 Mitigate identified device issues**

### Using AWS CLI

Lets look at creating mitigation action using CLI 

Command for creating mitigation action:


```
aws ml-iot create-mitigation-action
          --action-name <value>
          --role-arn <value>
          --action-params <value>
          [--tags <value>]
          [--cli-input-json | --cli-input-yaml]
          [--generate-cli-skeleton <value>]
          [--cli-auto-prompt <value>]
```

#
# Simulation 
### Lets do simulation using sample scripts

Before starting to test this make sure your aws CLI profile is up to date and working.

``` 
aws s3 ls 
``` 
Will give the result whether its working or not.

**Please note these scripts are for simulation purposes and not intended for Production usage (Use it at your own risk)** 

### First anomalous behaviour test

* We will use the following script (anom_simulator.py) to simulate anomalous behaviour

``` 
python3 anom_simulator.py --msg-size 2000 --count 5000 --sleep-time 0.25 --thing-name anom_thing_1 --group-name anom_group --policy allow_iot_operations --security-profile-name <FILL_Sec_Profile_Name> --region <FILL_Region> --account_id <FILL account-id> aws_profile <FILL ws-profile-name>

```

Let's look at this in detail we will be creating 2000 messages on MQTT topic (test/topic) and the script will automatically create thing name: anom_thing_1 with group name: anom_group, prior to running make sure you have ML Detect profile created and give that profile name in the command as well as other details as enlisted.

If you dont have any specific aws cli profile you can just give 'default' for aws_profile param, note param thing name can contain same thing name which already exist else it will give you error. Since this script will orchestrate all the setup for the thing and run the simulation.

While the script running you can go to AWS IoT Core and use test client and subscribe to following MQTT topic: test/topic

If its successful you will get following console output:

```
Launching setup of profiles....
Thing creation of anomaly_thing_x complete!
Found endpoint: aar4akmtxxxxx-ats.iot.eu-west-1.amazonaws.com
Policy anom_policy already exists.
Group anom_group already exists.
125da6bb0a8397dffced11854054a451d0b965ba24f3e518382c009d3e7c470e
Connecting to aar4akmtxxxxx-ats.iot.eu-west-1.amazonaws.com with client ID 'anomaly_thing_x'...
Connected!
Subscribing to topic 'test/topic'...
Subscribed with QoS.AT_LEAST_ONCE
Sending 5000 message(s)
Publishing message [1/5000] to topic 'test/topic': 2000
Sleeping for 0.25 seconds
Received message from topic 'test/topic': 2000
Publishing message [2/5000] to topic 'test/topic': 2000
Sleeping for 0.25 seconds
Received message from topic 'test/topic': 2000
Publishing message [3/5000] to topic 'test/topic': 2000
Sleeping for 0.25 seconds
```

### Second Shared Security certificate test

For this test we will use the following script: SharedCertSimulator.py, the script will do following:

It will create a new random thing name, thing group, a shared certificate and connect (and do nothing else).

For auditing test purpose you just need to make sure that Audit with Shared certs check is enabled run this test and run audit on shared certificates and you will see non-compliance in audit report.

Run with following command:
```
python SharedCertSimulator.py --endpoint <iot_endpoint> --region <aws_region>
```
Audit result:

![alt text](https://github.com/redmancodes/device-defender-ml/blob/main/image/image.png?raw=true)


