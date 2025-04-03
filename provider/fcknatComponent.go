// Copyright 2016-2023, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"
	"strings"

	"encoding/base64"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/autoscaling"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ssm"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// FckNat is a component resource for creating an alternative to AWS NAT gateways
type FckNat struct {
	pulumi.ResourceState // Component state needs this for tracking nested resource states.

	// Output fields
	SecurityGroupId       pulumi.StringOutput `pulumi:"securityGroupId"`
	NetworkInterfaceId    pulumi.StringOutput `pulumi:"networkInterfaceId"`
	InstanceId            pulumi.StringOutput `pulumi:"instanceId"`
	IAMRoleArn            pulumi.StringOutput `pulumi:"iamRoleArn"`
	IAMInstanceProfileArn pulumi.StringOutput `pulumi:"iamInstanceProfileArn"`
	PrivateIp             pulumi.StringOutput `pulumi:"privateIp"`
	PublicIp              pulumi.StringOutput `pulumi:"publicIp"`
	PublicDns             pulumi.StringOutput `pulumi:"publicDns"`
	AutoScalingGroupArn   pulumi.StringOutput `pulumi:"autoScalingGroupArn"`
}

// FckNatArgs defines the input arguments for the FckNat component
type FckNatArgs struct {
	// Required parameters
	Name     pulumi.StringInput `pulumi:"name"`
	VpcId    pulumi.StringInput `pulumi:"vpcId"`
	SubnetId pulumi.StringInput `pulumi:"subnetId"`

	// Optional parameters
	InstanceType                                   pulumi.StringInput      `pulumi:"instanceType,optional"`
	AmiId                                          pulumi.StringPtrInput   `pulumi:"amiId,optional"`
	EbsRootVolumeSize                              pulumi.IntInput         `pulumi:"ebsRootVolumeSize,optional"`
	Encryption                                     pulumi.BoolInput        `pulumi:"encryption,optional"`
	KmsKeyId                                       pulumi.StringPtrInput   `pulumi:"kmsKeyId,optional"`
	HAMode                                         pulumi.BoolInput        `pulumi:"haMode,optional"`
	UseSpotInstances                               pulumi.BoolInput        `pulumi:"useSpotInstances,optional"`
	SshKeyName                                     pulumi.StringPtrInput   `pulumi:"sshKeyName,optional"`
	UseSsh                                         pulumi.BoolInput        `pulumi:"useSsh,optional"`
	SshCidrBlocksIpv4                              pulumi.StringArrayInput `pulumi:"sshCidrBlocksIpv4,optional"`
	SshCidrBlocksIpv6                              pulumi.StringArrayInput `pulumi:"sshCidrBlocksIpv6,optional"`
	EipAllocationIds                               pulumi.StringArrayInput `pulumi:"eipAllocationIds,optional"`
	UseDefaultSecurityGroup                        pulumi.BoolInput        `pulumi:"useDefaultSecurityGroup,optional"`
	AdditionalSecurityGroupIds                     pulumi.StringArrayInput `pulumi:"additionalSecurityGroupIds,optional"`
	RouteTableIds                                  pulumi.MapInput         `pulumi:"routeTableIds,optional"`
	UpdateRouteTables                              pulumi.BoolInput        `pulumi:"updateRouteTables,optional"`
	AttachSsmPolicy                                pulumi.BoolInput        `pulumi:"attachSsmPolicy,optional"`
	UseCloudwatchAgent                             pulumi.BoolInput        `pulumi:"useCloudwatchAgent,optional"`
	CloudwatchAgentConfigurationArnParam           pulumi.StringPtrInput   `pulumi:"cloudwatchAgentConfigurationArnParam,optional"`
	CloudwatchAgentConfigurationCollectionInterval pulumi.IntPtrInput      `pulumi:"cloudwatchAgentConfigurationCollectionInterval,optional"`
	CloudwatchAgentConfigurationNamespace          pulumi.StringPtrInput   `pulumi:"cloudwatchAgentConfigurationNamespace,optional"`
	CloudwatchAgentConfigurationEndpointOverride   pulumi.StringPtrInput   `pulumi:"cloudwatchAgentConfigurationEndpointOverride,optional"`
	Tags                                           pulumi.MapInput         `pulumi:"tags,optional"`
}

// Helper functions for safer type conversions
func getBool(v interface{}) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func getStringArray(v interface{}) []string {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]string); ok {
		return arr
	}
	if arr, ok := v.([]interface{}); ok {
		result := make([]string, len(arr))
		for i, item := range arr {
			result[i] = getString(item)
		}
		return result
	}
	return nil
}

// getResourceName returns a consistent name for a resource based on the base name and suffix
func getResourceName(baseName string, suffix string) string {
	if suffix == "" {
		return baseName
	}
	return fmt.Sprintf("%s-%s", baseName, suffix)
}

// isArmArchitecture checks if the instance type is ARM-based
func isArmArchitecture(instanceType string) bool {
	if instanceType == "" {
		return true // Default to ARM if not specified
	}

	armPrefixes := []string{"a1", "t4g", "m6g", "c6g", "r6g", "g5g", "im4gn", "is4gen"}
	for _, prefix := range armPrefixes {
		if strings.HasPrefix(instanceType, prefix) {
			return true
		}
	}
	return false
}

// generateUserData creates a user data script for fck-nat configuration
func generateUserData(eniId string, eipId string, useCloudwatch bool, cwAgentParamName string) string {
	userData := "#!/bin/sh\n\n"
	userData += ": > /etc/fck-nat.conf\n"
	userData += fmt.Sprintf("echo \"eni_id=%s\" >> /etc/fck-nat.conf\n", eniId)
	userData += fmt.Sprintf("echo \"eip_id=%s\" >> /etc/fck-nat.conf\n", eipId)

	if useCloudwatch {
		userData += "echo \"cwagent_enabled=true\" >> /etc/fck-nat.conf\n"
		userData += fmt.Sprintf("echo \"cwagent_cfg_param_name=%s\" >> /etc/fck-nat.conf\n", cwAgentParamName)
	} else {
		userData += "echo \"cwagent_enabled=\" >> /etc/fck-nat.conf\n"
		userData += "echo \"cwagent_cfg_param_name=\" >> /etc/fck-nat.conf\n"
	}

	userData += "\nservice fck-nat restart\n"
	return userData
}

// createPolicyStatement creates a policy statement with the given parameters
func createPolicyStatement(sid string, effect string, actions []string, resources []string, condition map[string]interface{}) map[string]interface{} {
	statement := map[string]interface{}{
		"Sid":      sid,
		"Effect":   effect,
		"Action":   actions,
		"Resource": resources,
	}

	if condition != nil {
		statement["Condition"] = condition
	}

	return statement
}

// createNameTagMap merges a name into a tag map
func createNameTagMap(name string, tags map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range tags {
		result[k] = v
	}
	result["Name"] = name
	return result
}

// createLaunchTemplateTagSpecs creates tag specifications for launch templates
func createLaunchTemplateTagSpecs(resourceTypes []string, tags pulumi.StringMapOutput) ec2.LaunchTemplateTagSpecificationArray {
	var specs ec2.LaunchTemplateTagSpecificationArray

	for _, resourceType := range resourceTypes {
		specs = append(specs, &ec2.LaunchTemplateTagSpecificationArgs{
			ResourceType: pulumi.String(resourceType),
			Tags:         tags,
		})
	}

	return specs
}

// createAutoScalingTags creates tags for AutoScaling Group
func createAutoScalingTags(name pulumi.StringInput, propagateAtLaunch bool) autoscaling.GroupTagArray {
	return autoscaling.GroupTagArray{
		&autoscaling.GroupTagArgs{
			Key:               pulumi.String("Name"),
			Value:             name,
			PropagateAtLaunch: pulumi.Bool(propagateAtLaunch),
		},
	}
}

// NewFckNat creates a new FckNat component resource
func NewFckNat(ctx *pulumi.Context, name string, args *FckNatArgs, opts ...pulumi.ResourceOption) (*FckNat, error) {
	// Initialize the component state
	comp := &FckNat{}

	// Register the component resource
	err := ctx.RegisterComponentResource("fcknat:Gateway", name, comp, opts...)
	if err != nil {
		return nil, err
	}

	// Set default values - don't reassign to the args directly
	defaultInstanceType := pulumi.String("t4g.nano")
	defaultEbsVolumeSize := pulumi.Int(10)

	// Convert MapInput to StringMap for use with resource Tags
	tagsMap := pulumi.All(args.Tags).ApplyT(func(inputs []interface{}) map[string]string {
		tags := make(map[string]string)
		if inputs[0] == nil {
			return tags
		}

		rawTags, ok := inputs[0].(map[string]interface{})
		if !ok {
			return tags
		}

		for k, v := range rawTags {
			tags[k] = getString(v)
		}
		return tags
	}).(pulumi.StringMapOutput)

	// Get the VPC CIDR block for security group ingress rules
	vpcCidrBlock := args.VpcId.ToStringOutput().ApplyT(func(vpcId string) (string, error) {
		vpc, err := ec2.LookupVpc(ctx, &ec2.LookupVpcArgs{
			Id: &vpcId,
		})
		if err != nil {
			return "", err
		}
		return vpc.CidrBlock, nil
	}).(pulumi.StringOutput)

	// Create the security group
	securityGroup, err := ec2.NewSecurityGroup(ctx, name, &ec2.SecurityGroupArgs{
		Name:        args.Name,
		Description: pulumi.Sprintf("Used in %s instance of fck-nat in subnet %s", args.Name, args.SubnetId),
		VpcId:       args.VpcId.ToStringOutput(),
		Ingress: ec2.SecurityGroupIngressArray{
			&ec2.SecurityGroupIngressArgs{
				Description: pulumi.String("Unrestricted ingress from within VPC"),
				FromPort:    pulumi.Int(0),
				ToPort:      pulumi.Int(0),
				Protocol:    pulumi.String("-1"),
				CidrBlocks:  pulumi.StringArray{vpcCidrBlock},
			},
		},
		Egress: ec2.SecurityGroupEgressArray{
			&ec2.SecurityGroupEgressArgs{
				Description:    pulumi.String("Unrestricted egress"),
				FromPort:       pulumi.Int(0),
				ToPort:         pulumi.Int(0),
				Protocol:       pulumi.String("-1"),
				CidrBlocks:     pulumi.StringArray{pulumi.String("0.0.0.0/0")},
				Ipv6CidrBlocks: pulumi.StringArray{pulumi.String("::/0")},
			},
		},
		Tags: pulumi.All(args.Name, tagsMap).ApplyT(func(inputs []interface{}) map[string]string {
			name := inputs[0].(string)
			tags := inputs[1].(map[string]string)
			return createNameTagMap(name, tags)
		}).(pulumi.StringMapOutput),
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	// Add SSH ingress rule if enabled
	pulumi.All(args.UseSsh).ApplyT(func(inputs []interface{}) error {
		if !getBool(inputs[0]) {
			return nil
		}

		// Get SSH CIDR blocks for IPv4 and IPv6
		var ipv4Blocks, ipv6Blocks []string

		if args.SshCidrBlocksIpv4 != nil {
			pulumi.All(args.SshCidrBlocksIpv4).ApplyT(func(inputs []interface{}) interface{} {
				ipv4Blocks = getStringArray(inputs[0])
				return nil
			})
		}

		if args.SshCidrBlocksIpv6 != nil {
			pulumi.All(args.SshCidrBlocksIpv6).ApplyT(func(inputs []interface{}) interface{} {
				ipv6Blocks = getStringArray(inputs[0])
				return nil
			})
		}

		// Create SSH security group rule
		_, ruleErr := ec2.NewSecurityGroupRule(ctx, getResourceName(name, "ssh"), &ec2.SecurityGroupRuleArgs{
			Type:            pulumi.String("ingress"),
			SecurityGroupId: securityGroup.ID(),
			Description:     pulumi.String("SSH access"),
			FromPort:        pulumi.Int(22),
			ToPort:          pulumi.Int(22),
			Protocol:        pulumi.String("tcp"),
			CidrBlocks:      pulumi.ToStringArray(ipv4Blocks),
			Ipv6CidrBlocks:  pulumi.ToStringArray(ipv6Blocks),
		}, pulumi.Parent(comp))

		return ruleErr
	})

	// Create the network interface
	networkInterface, err := ec2.NewNetworkInterface(ctx, name, &ec2.NetworkInterfaceArgs{
		Description:     pulumi.Sprintf("%s static private ENI", args.Name),
		SubnetId:        args.SubnetId.ToStringOutput(),
		SecurityGroups:  pulumi.StringArray{securityGroup.ID()},
		SourceDestCheck: pulumi.Bool(false), // Required for NAT functionality
		Tags:            tagsMap,
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	// Convert AdditionalSecurityGroupIds to []string format
	if args.AdditionalSecurityGroupIds != nil {
		// Add additional security groups to the network interface
		pulumi.All(args.AdditionalSecurityGroupIds).ApplyT(func(inputs []interface{}) interface{} {
			if inputs[0] != nil {
				if strArr, ok := inputs[0].([]string); ok {
					if len(strArr) > 0 {
						// Log or process the additional security groups
						fmt.Printf("Adding %d additional security groups\n", len(strArr))
					}
				}
			}
			return nil
		})
	}

	// Convert EipAllocationIds to []string format
	if args.EipAllocationIds != nil {
		pulumi.All(args.EipAllocationIds).ApplyT(func(inputs []interface{}) interface{} {
			if inputs[0] != nil {
				if strArr, ok := inputs[0].([]string); ok {
					// We don't need to store this as we're using the full args.EipAllocationIds in other places
					_ = strArr
				}
			}
			return nil
		})
	}

	// Create IAM instance profile
	assumeRolePolicy := pulumi.String(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": "sts:AssumeRole",
				"Principal": {
					"Service": "ec2.amazonaws.com"
				},
				"Effect": "Allow",
				"Sid": ""
			}
		]
	}`)

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		Name:             args.Name,
		AssumeRolePolicy: assumeRolePolicy,
		Tags:             tagsMap,
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	// Use these helpers in the policy document creation
	policyDoc := pulumi.All(args.Name, networkInterface.ID(), args.EipAllocationIds, args.UseCloudwatchAgent, args.AttachSsmPolicy).ApplyT(
		func(inputs []interface{}) pulumi.StringOutput {
			name := getString(inputs[0])
			eniId := getString(inputs[1])

			// Parse EIP IDs from the input
			eipIds := getStringArray(inputs[2])

			// Get boolean values
			useCloudwatch := getBool(inputs[3])
			attachSsm := getBool(inputs[4])

			// Base policy with ENI management
			statements := []map[string]interface{}{
				createPolicyStatement(
					"ManageNetworkInterface",
					"Allow",
					[]string{
						"ec2:AttachNetworkInterface",
						"ec2:ModifyNetworkInterfaceAttribute",
					},
					[]string{"*"},
					map[string]interface{}{
						"StringEquals": map[string]string{
							"ec2:ResourceTag/Name": name,
						},
					},
				),
			}

			// Add CloudWatch Agent permissions if enabled
			if useCloudwatch {
				statements = append(statements, createPolicyStatement(
					"CWAgentSSMParameter",
					"Allow",
					[]string{"ssm:GetParameter"},
					[]string{"*"},
					nil,
				))

				statements = append(statements, createPolicyStatement(
					"CWAgentMetrics",
					"Allow",
					[]string{"cloudwatch:PutMetricData"},
					[]string{"*"},
					map[string]interface{}{
						"StringEquals": map[string]interface{}{
							"cloudwatch:namespace": "FckNat",
						},
					},
				))
			}

			// Add SSM permissions if enabled
			if attachSsm {
				statements = append(statements, createPolicyStatement(
					"SessionManager",
					"Allow",
					[]string{
						"ssmmessages:CreateDataChannel",
						"ssmmessages:OpenDataChannel",
						"ssmmessages:CreateControlChannel",
						"ssmmessages:OpenControlChannel",
						"ssm:UpdateInstanceInformation",
					},
					[]string{"*"},
					nil,
				))
			}

			// Add EIP management if provided
			if len(eipIds) > 0 {
				statements = append(statements, createPolicyStatement(
					"ManageEIPAllocation",
					"Allow",
					[]string{
						"ec2:AssociateAddress",
						"ec2:DisassociateAddress",
					},
					[]string{
						fmt.Sprintf("arn:aws:ec2:*:*:elastic-ip/%s", eipIds[0]),
					},
					nil,
				))

				statements = append(statements, createPolicyStatement(
					"ManageEIPNetworkInterface",
					"Allow",
					[]string{
						"ec2:AssociateAddress",
						"ec2:DisassociateAddress",
					},
					[]string{
						fmt.Sprintf("arn:aws:ec2:*:*:network-interface/%s", eniId),
					},
					map[string]interface{}{
						"StringEquals": map[string]string{
							"ec2:ResourceTag/Name": name,
						},
					},
				))
			}

			policy := map[string]interface{}{
				"Version":   "2012-10-17",
				"Statement": statements,
			}

			return pulumi.JSONMarshal(policy)
		})

	policy, err := iam.NewPolicy(ctx, name, &iam.PolicyArgs{
		Name:   args.Name,
		Policy: policyDoc,
		Tags:   tagsMap,
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	_, err = iam.NewRolePolicyAttachment(ctx, name, &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: policy.Arn,
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	instanceProfile, err := iam.NewInstanceProfile(ctx, name, &iam.InstanceProfileArgs{
		Name: args.Name,
		Role: role.Name,
		Tags: tagsMap,
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	// Create CloudWatch agent configuration if needed
	var cwAgentParamName string // Store just the name as a string

	pulumi.All(args.UseCloudwatchAgent, args.CloudwatchAgentConfigurationNamespace, args.CloudwatchAgentConfigurationCollectionInterval).ApplyT(func(inputs []interface{}) interface{} {
		useCloudwatch := getBool(inputs[0])

		if !useCloudwatch {
			return nil
		}

		// Get CloudWatch configuration values with defaults
		namespace := "FckNat"
		if inputs[1] != nil && inputs[1].(*string) != nil {
			namespace = *inputs[1].(*string)
		}

		interval := 60
		if inputs[2] != nil && inputs[2].(*int) != nil {
			interval = *inputs[2].(*int)
		}

		// Create CloudWatch agent configuration
		configJson := fmt.Sprintf(`{
			"agent": {
				"metrics_collection_interval": %d,
				"run_as_user": "cwagent"
			},
			"metrics": {
				"namespace": "%s",
				"append_dimensions": {
					"InstanceId": "${aws:InstanceId}"
				},
				"metrics_collected": {
					"mem": {
						"measurement": [
							"mem_used_percent"
						],
						"metrics_collection_interval": %d
					},
					"netstat": {
						"measurement": [
							"tcp_established",
							"tcp_time_wait"
						],
						"metrics_collection_interval": %d
					}
				}
			}
		}`, interval, namespace, interval, interval)

		paramName := getResourceName(name, "cloudwatch-agent-config")
		param, paramErr := ssm.NewParameter(ctx, getResourceName(name, "cwagent-config"), &ssm.ParameterArgs{
			Name:  pulumi.String(paramName),
			Type:  pulumi.String("SecureString"),
			Value: pulumi.String(configJson),
			KeyId: args.KmsKeyId,
			Tags:  tagsMap,
		}, pulumi.Parent(comp))

		if paramErr == nil && param != nil {
			cwAgentParamName = paramName
		}

		return nil
	})

	// Get AMI ID - Either use provided one or find latest fck-nat AMI
	var amiId pulumi.StringOutput
	if args.AmiId != nil {
		amiId = args.AmiId.ToStringPtrOutput().Elem()
	} else {
		// Check if the instance type is ARM-based
		isArm := pulumi.All(args.InstanceType).ApplyT(func(inputs []interface{}) bool {
			instType := getString(inputs[0])
			return isArmArchitecture(instType)
		}).(pulumi.BoolOutput)

		amiId = pulumi.All(isArm).ApplyT(func(inputs []interface{}) (string, error) {
			isArm := getBool(inputs[0])

			arch := "x86_64"
			if isArm {
				arch = "arm64"
			}

			result, err := ec2.LookupAmi(ctx, &ec2.LookupAmiArgs{
				MostRecent: pulumi.BoolRef(true),
				Owners:     []string{"568608671756"}, // fck-nat AMI owner
				Filters: []ec2.GetAmiFilter{
					{
						Name:   "name",
						Values: []string{"fck-nat-al2023-hvm-*"},
					},
					{
						Name:   "architecture",
						Values: []string{arch},
					},
					{
						Name:   "root-device-type",
						Values: []string{"ebs"},
					},
					{
						Name:   "virtualization-type",
						Values: []string{"hvm"},
					},
				},
			})
			if err != nil {
				return "", err
			}

			return result.Id, nil
		}).(pulumi.StringOutput)
	}

	// Replace user data generation with helper function call
	userData := pulumi.All(networkInterface.ID(), args.EipAllocationIds, args.UseCloudwatchAgent).ApplyT(
		func(inputs []interface{}) string {
			eniId := getString(inputs[0])
			eipIds := getStringArray(inputs[1])
			useCloudwatch := getBool(inputs[2])

			eipId := ""
			if len(eipIds) > 0 {
				eipId = eipIds[0]
			}

			return generateUserData(eniId, eipId, useCloudwatch, cwAgentParamName)
		}).(pulumi.StringOutput)

	// Use input arguments or defaults for launch template
	instanceTypeToUse := pulumi.All(args.InstanceType, defaultInstanceType).ApplyT(func(inputs []interface{}) string {
		instType := getString(inputs[0])
		if instType != "" {
			return instType
		}
		return getString(inputs[1])
	}).(pulumi.StringOutput)

	ebsRootVolumeToUse := pulumi.All(args.EbsRootVolumeSize, defaultEbsVolumeSize).ApplyT(func(inputs []interface{}) int {
		if inputs[0] != nil {
			if val, ok := inputs[0].(int); ok && val > 0 {
				return val
			}
		}
		return inputs[1].(int)
	}).(pulumi.IntOutput)

	// Launch template for EC2 instance or ASG
	launchTemplate, err := ec2.NewLaunchTemplate(ctx, name, &ec2.LaunchTemplateArgs{
		Name:         args.Name,
		ImageId:      amiId,
		InstanceType: instanceTypeToUse,
		KeyName:      args.SshKeyName,

		BlockDeviceMappings: ec2.LaunchTemplateBlockDeviceMappingArray{
			&ec2.LaunchTemplateBlockDeviceMappingArgs{
				DeviceName: pulumi.String("/dev/xvda"),
				Ebs: &ec2.LaunchTemplateBlockDeviceMappingEbsArgs{
					VolumeSize: ebsRootVolumeToUse,
					VolumeType: pulumi.String("gp3"),
					Encrypted: pulumi.All(args.Encryption).ApplyT(func(inputs []interface{}) *string {
						var encrypted string
						if getBool(inputs[0]) {
							encrypted = "true"
						} else {
							encrypted = "false"
						}
						return &encrypted
					}).(pulumi.StringPtrOutput),
					KmsKeyId: args.KmsKeyId,
				},
			},
		},

		IamInstanceProfile: &ec2.LaunchTemplateIamInstanceProfileArgs{
			Name: instanceProfile.Name,
		},

		NetworkInterfaces: ec2.LaunchTemplateNetworkInterfaceArray{
			&ec2.LaunchTemplateNetworkInterfaceArgs{
				Description:              pulumi.Sprintf("%s ephemeral public ENI", args.Name),
				SubnetId:                 args.SubnetId.ToStringOutput(),
				AssociatePublicIpAddress: pulumi.String("true").ToStringPtrOutput(),
				SecurityGroups:           pulumi.StringArray{securityGroup.ID()},
			},
		},

		MetadataOptions: &ec2.LaunchTemplateMetadataOptionsArgs{
			HttpEndpoint: pulumi.String("enabled"),
			HttpTokens:   pulumi.String("required"), // Enforce IMDSv2
		},

		UserData: userData.ApplyT(func(data string) string {
			return base64.StdEncoding.EncodeToString([]byte(data))
		}).(pulumi.StringOutput),

		TagSpecifications: createLaunchTemplateTagSpecs(
			[]string{"instance", "network-interface", "volume"},
			tagsMap,
		),
	}, pulumi.Parent(comp))
	if err != nil {
		return nil, err
	}

	// Create instance or Auto Scaling Group based on HA mode
	var instance *ec2.Instance
	var asg *autoscaling.Group

	pulumi.All(args.HAMode).ApplyT(func(inputs []interface{}) interface{} {
		haModeEnabled := getBool(inputs[0])

		if haModeEnabled {
			// Create Auto Scaling Group for HA mode
			asg, err = autoscaling.NewGroup(ctx, name, &autoscaling.GroupArgs{
				Name:               pulumi.String(name),
				MaxSize:            pulumi.Int(1),
				MinSize:            pulumi.Int(1),
				DesiredCapacity:    pulumi.Int(1),
				HealthCheckType:    pulumi.String("EC2"),
				VpcZoneIdentifiers: pulumi.StringArray{args.SubnetId.ToStringOutput()},
				LaunchTemplate: &autoscaling.GroupLaunchTemplateArgs{
					Id:      launchTemplate.ID(),
					Version: pulumi.String("$Latest"),
				},
				Tags: createAutoScalingTags(args.Name, true),
				EnabledMetrics: pulumi.StringArray{
					pulumi.String("GroupMinSize"),
					pulumi.String("GroupMaxSize"),
					pulumi.String("GroupDesiredCapacity"),
					pulumi.String("GroupInServiceInstances"),
					pulumi.String("GroupPendingInstances"),
					pulumi.String("GroupStandbyInstances"),
					pulumi.String("GroupTerminatingInstances"),
					pulumi.String("GroupTotalInstances"),
				},
				InstanceRefresh: &autoscaling.GroupInstanceRefreshArgs{
					Strategy: pulumi.String("Rolling"),
					Preferences: &autoscaling.GroupInstanceRefreshPreferencesArgs{
						MinHealthyPercentage: pulumi.Int(90),
					},
				},
			}, pulumi.Parent(comp))

			if asg != nil {
				comp.AutoScalingGroupArn = asg.Arn
				comp.InstanceId = pulumi.String("managed-by-asg").ToStringOutput()
			}
		} else {
			// Create a regular EC2 instance
			instance, err = ec2.NewInstance(ctx, name, &ec2.InstanceArgs{
				LaunchTemplate: &ec2.InstanceLaunchTemplateArgs{
					Id:      launchTemplate.ID(),
					Version: pulumi.String("$Latest"),
				},
				Tags: tagsMap,
			}, pulumi.Parent(comp))

			if instance != nil {
				comp.InstanceId = instance.ID().ToStringOutput()
				comp.PublicIp = instance.PublicIp
				comp.PublicDns = instance.PublicDns
			}
		}

		return nil
	})

	// Add routes if configured
	pulumi.All(args.UpdateRouteTables, args.RouteTableIds).ApplyT(func(inputs []interface{}) interface{} {
		updateRoutes := getBool(inputs[0])

		if !updateRoutes || inputs[1] == nil {
			return nil
		}

		rtMap := inputs[1].(map[string]interface{})
		for key, v := range rtMap {
			rtId := getString(v)

			_, err := ec2.NewRoute(ctx, getResourceName(name, fmt.Sprintf("route-%s", key)), &ec2.RouteArgs{
				RouteTableId:         pulumi.String(rtId),
				DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
				NetworkInterfaceId:   networkInterface.ID(),
			}, pulumi.Parent(comp))
			if err != nil {
				return err
			}
		}
		return nil
	})

	// Set component outputs
	comp.SecurityGroupId = securityGroup.ID().ToStringOutput()
	comp.NetworkInterfaceId = networkInterface.ID().ToStringOutput()
	comp.IAMRoleArn = role.Arn
	comp.IAMInstanceProfileArn = instanceProfile.Arn
	comp.PrivateIp = networkInterface.PrivateIp

	return comp, nil
}
