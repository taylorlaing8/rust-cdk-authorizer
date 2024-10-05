#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AppStack } from '../lib/app-stack';
import { config } from 'dotenv';
config();

const CDK_DEFAULT_ACCOUNT = process.env.CDK_DEFAULT_ACCOUNT!;
const CDK_DEFAULT_REGION = process.env.CDK_DEFAULT_REGION!;
const SERVICE = process.env.SERVICE!;
const STAGE = process.env.STAGE!;

const appStackName = `${SERVICE}-${STAGE}-app`;

const app = new cdk.App();

new AppStack(app, appStackName, {
	description: `${SERVICE} ${STAGE} application stack`,
	service: SERVICE,
	stage: STAGE,
	subscriptionEmail: 'aws_alarm@classifind.app',
	env: {
		account: CDK_DEFAULT_ACCOUNT,
		region: CDK_DEFAULT_REGION,
	},
});
