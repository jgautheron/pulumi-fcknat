package main

import (
	"example.com/pulumi-fcknat/sdk/go/fcknat"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		myFckNat, err := fcknat.NewFckNat(ctx, "myFckNat", &fcknat.FckNatArgs{
			Name:              pulumi.String("example-fcknat"),
			VpcId:             pulumi.String("vpc-12345678"),
			SubnetId:          pulumi.String("subnet-12345678"),
			InstanceType:      pulumi.String("t4g.nano"),
			HaMode:            pulumi.Bool(false),
			UseSpotInstances:  pulumi.Bool(true),
			UseSsh:            pulumi.Bool(false),
			Encryption:        pulumi.Bool(true),
			UpdateRouteTables: pulumi.Bool(true),
			AttachSsmPolicy:   pulumi.Bool(true),
			Tags: pulumi.Map{
				"Environment": pulumi.Any("dev"),
				"ManagedBy":   pulumi.Any("pulumi"),
			},
		})
		if err != nil {
			return err
		}
		ctx.Export("securityGroupId", pulumi.StringMap{
			"value": myFckNat.SecurityGroupId,
		})
		ctx.Export("instanceId", pulumi.StringMap{
			"value": myFckNat.InstanceId,
		})
		ctx.Export("publicIp", pulumi.StringMap{
			"value": myFckNat.PublicIp,
		})
		return nil
	})
}
