import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as codeDeploy from 'aws-cdk-lib/aws-codedeploy';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import {
	Code,
	Function,
	Runtime,
	Architecture,
	Tracing,
	Alias,
} from 'aws-cdk-lib/aws-lambda';

export interface AppStackProps extends cdk.StackProps {
	stage: string;
	service: string;
	subscriptionEmail: string;
}

export class AppStack extends cdk.Stack {
	constructor(scope: Construct, id: string, props: AppStackProps) {
		super(scope, id, props);

		// TODO: Create topic that will email errors to dev@marketlink.app
		const snsTopic = new sns.Topic(this, 'SnsTopic', {
			topicName: `${this.stackName}-alarm`,
		});

		if (this.isProdStage(props.stage)) {
			snsTopic.addSubscription(
				new subscriptions.UrlSubscription(props.subscriptionEmail)
			);
		}

		const authorizerConfigPath = '/authorizer/config';

		const authorizerFunction = new Function(this, 'AuthorizerFunctionLambda', {
			functionName: `${this.stackName}-auth`,
			code: Code.fromAsset('./auth/target/lambda/cf-authorizer'),
			runtime: Runtime.PROVIDED_AL2,
			architecture: Architecture.ARM_64,
			memorySize: 1024,
			timeout: cdk.Duration.seconds(10),
			tracing: Tracing.ACTIVE,
			handler: 'main',
			environment: {
				AUTHORIZER_CONFIG_PATH: authorizerConfigPath,
			},
		});

		new logs.LogGroup(this, 'AuthorizerFunctionLogGroup', {
			logGroupName: `/aws/lambda/${authorizerFunction.functionName}`,
			retention: this.isProdStage(props.stage)
				? logs.RetentionDays.ONE_YEAR
				: logs.RetentionDays.ONE_WEEK,
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});

		const authorizerFunctionAlias = new Alias(
			this,
			'AuthorizerFunctionAlias',
			{
				aliasName: 'LIVE',
				version: authorizerFunction.currentVersion,
			}
		);

		const authorizerFunctionErrors = new cloudwatch.Alarm(
			this,
			'AuthorizerFunctionErrors',
			{
				alarmDescription: 'The latest deployment errors > 0',
				metric: authorizerFunctionAlias.metricErrors({
					statistic: 'Sum',
					period: cdk.Duration.minutes(1),
				}),
				threshold: 1,
				evaluationPeriods: 1,
				actionsEnabled: true,
				comparisonOperator:
					cloudwatch.ComparisonOperator
						.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
			}
		);

		authorizerFunctionErrors.addAlarmAction(
			new actions.SnsAction(snsTopic)
		);

		const lambdaDeploymentConfig = this.isProdStage(props.stage)
			? codeDeploy.LambdaDeploymentConfig.CANARY_10PERCENT_10MINUTES
			: codeDeploy.LambdaDeploymentConfig.ALL_AT_ONCE;

		new codeDeploy.LambdaDeploymentGroup(
			this,
			'AuthorizerDeploymentGroup',
			{
				alias: authorizerFunctionAlias,
				deploymentConfig: lambdaDeploymentConfig,
				alarms: [authorizerFunctionErrors],
			}
		);

		authorizerFunctionAlias.addToRolePolicy(
			new iam.PolicyStatement({
				effect: iam.Effect.ALLOW,
				actions: ['ssm:GetParameter'],
				resources: [
					`arn:aws:ssm:${this.region}:${this.account}:parameter${authorizerConfigPath}`,
				],
			})
		);

		// TODO: Check that this is needed
		authorizerFunctionAlias.addToRolePolicy(
			new iam.PolicyStatement({
				effect: iam.Effect.ALLOW,
				actions: ['kms:Decrypt'],
				resources: ['*'],
			})
		);

		new cdk.CfnOutput(this, 'AuthFunctionArn', {
			value: authorizerFunctionAlias.functionArn,
		});
	}

	private isCiCdStage(stage: string): boolean {
		return ['dev', 'stage', 'prod'].includes(stage);
	}

	private isProdStage(stage: string): boolean {
		return 'prod' === stage;
	}
}
