#!/usr/bin/env python3
from cdk_nag import AwsSolutionsChecks
import aws_cdk as cdk
from aws_cdk import Aspects

from guardduty_eb.guardduty_eb_stack import GuarddutyEbStack

app = cdk.App()
Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
GuarddutyEbStack(app, "GuarddutyEbStack", env=cdk.Environment(

))

app.synth()
