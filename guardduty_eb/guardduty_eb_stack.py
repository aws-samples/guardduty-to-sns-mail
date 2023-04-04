import aws_cdk
from aws_cdk import (
    Stack,
    aws_sns,
    aws_events,
    aws_sns_subscriptions,
    aws_iam,
    aws_kms
)

from constructs import Construct


class GuarddutyEbStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        mail_parameter = aws_cdk.CfnParameter(self, "Mail", type="String",
                                              description="Mail to send findings to")
        severity_threshold = aws_cdk.CfnParameter(self, "SeverityThreshold",
                                                  type="Number",
                                                  description="Minimum severity to send the finding through mail (7 means only high severity)",
                                                  default=7)

        # KMS Key
        # EventBridge can't use default KMS keys when publishing to SNS topics, so we must create a new CMK key for this purpose
        kms_key = aws_kms.Key(self, "KMSCMKKey",
                              enable_key_rotation=True,
                              description="KMS CMK Key to Encrypt SNS Topics",
                              )

        kms_key.add_to_resource_policy(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            principals=[aws_iam.ServicePrincipal("events.amazonaws.com")],
            resources=["*"]
        ))
        kms_key.add_to_resource_policy(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            principals=[aws_iam.ServicePrincipal("sns.amazonaws.com")],
            resources=["*"]
        ))

        # SNS Topic
        # key_alias = aws_kms.Alias.from_alias_name(self, "DefaultKey", "alias/aws/sns")
        sns = aws_sns.Topic(self, "SnsTopic", topic_name="Guardduty-to-mail", master_key=kms_key)
        topic_policy = aws_sns.TopicPolicy(self, "TopicPolicy",
                                           topics=[sns],
                                           )

        # Policy to prohibit non HTTPS api calls
        topic_policy.document.add_statements(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.DENY,
            actions=["sns:Publish"],
            principals=[aws_iam.AnyPrincipal()],
            resources=[sns.topic_arn],
            conditions={"Bool": {"aws:SecureTransport": False}}
        ))
        topic_policy.document.add_statements(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["sns:Publish"],
            principals=[aws_iam.ServicePrincipal("events.amazonaws.com")],
            resources=[sns.topic_arn],
        ))

        # SNS Subscription to mail provided
        mail_subscription = aws_sns_subscriptions.EmailSubscription(email_address=mail_parameter.value_as_string)
        sns.add_subscription(mail_subscription)

        # EventBridge default bus
        bus = aws_events.EventBus.from_event_bus_name(self, "DefaultBus", event_bus_name="default")

        # Event Bridge InputTransformer
        transform_property = aws_events.CfnRule.InputTransformerProperty(
            input_template="""
"You have a severity <severity> GuardDuty finding type <Finding_Type> in the <region> region."
"Finding Description:"
"<Finding_description>."
"For more details open the GuardDuty console at https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?search=id%3D<Finding_ID> "
""",
            input_paths_map={
                "severity": "$.detail.severity",
                "Finding_ID": "$.detail.id",
                "Finding_Type": "$.detail.type",
                "region": "$.region",
                "Finding_description": "$.detail.description"
            }
        )

        # Event Bridge Target
        target_props = aws_events.CfnRule.TargetProperty(
            arn=sns.topic_arn,
            id="to-sns",
            input_transformer=transform_property,
            # role=eb_role.role_arn
        )

        # Event Bridge Rule
        to_sns_rule = aws_events.CfnRule(self,
                                         "EB-rule-to-SNS",
                                         description="Forwards GuardDuty findings to SNS",
                                         event_bus_name=bus.event_bus_name,
                                         event_pattern={
                                             "source": ["aws.guardduty"],
                                             "detail-type": ["GuardDuty Finding"],
                                             "detail": {
                                                 "severity": [{
                                                     "numeric": [">=", severity_threshold.value_as_number]
                                                 }]
                                             }
                                         },
                                         targets=[
                                             target_props,
                                         ]
                                         )

        # Generate CloudFormtion
        # cdk synth --no-version-reporting --path-metadata false --asset-metadata false
