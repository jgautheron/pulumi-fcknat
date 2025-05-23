// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export class FckNat extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'fcknat:Gateway:FckNat';

    /**
     * Returns true if the given object is an instance of FckNat.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FckNat {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FckNat.__pulumiType;
    }

    public /*out*/ readonly autoScalingGroupArn!: pulumi.Output<string>;
    public /*out*/ readonly iamInstanceProfileArn!: pulumi.Output<string>;
    public /*out*/ readonly iamRoleArn!: pulumi.Output<string>;
    public /*out*/ readonly instanceId!: pulumi.Output<string>;
    public /*out*/ readonly networkInterfaceId!: pulumi.Output<string>;
    public /*out*/ readonly privateIp!: pulumi.Output<string>;
    public /*out*/ readonly publicDns!: pulumi.Output<string>;
    public /*out*/ readonly publicIp!: pulumi.Output<string>;
    public /*out*/ readonly securityGroupId!: pulumi.Output<string>;

    /**
     * Create a FckNat resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FckNatArgs, opts?: pulumi.ComponentResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (!opts.id) {
            if ((!args || args.name === undefined) && !opts.urn) {
                throw new Error("Missing required property 'name'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            if ((!args || args.vpcId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vpcId'");
            }
            resourceInputs["additionalSecurityGroupIds"] = args ? args.additionalSecurityGroupIds : undefined;
            resourceInputs["amiId"] = args ? args.amiId : undefined;
            resourceInputs["attachSsmPolicy"] = args ? args.attachSsmPolicy : undefined;
            resourceInputs["cloudwatchAgentConfigurationArnParam"] = args ? args.cloudwatchAgentConfigurationArnParam : undefined;
            resourceInputs["cloudwatchAgentConfigurationCollectionInterval"] = args ? args.cloudwatchAgentConfigurationCollectionInterval : undefined;
            resourceInputs["cloudwatchAgentConfigurationEndpointOverride"] = args ? args.cloudwatchAgentConfigurationEndpointOverride : undefined;
            resourceInputs["cloudwatchAgentConfigurationNamespace"] = args ? args.cloudwatchAgentConfigurationNamespace : undefined;
            resourceInputs["ebsRootVolumeSize"] = args ? args.ebsRootVolumeSize : undefined;
            resourceInputs["eipAllocationIds"] = args ? args.eipAllocationIds : undefined;
            resourceInputs["encryption"] = args ? args.encryption : undefined;
            resourceInputs["haMode"] = args ? args.haMode : undefined;
            resourceInputs["instanceType"] = args ? args.instanceType : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["routeTableIds"] = args ? args.routeTableIds : undefined;
            resourceInputs["sshCidrBlocksIpv4"] = args ? args.sshCidrBlocksIpv4 : undefined;
            resourceInputs["sshCidrBlocksIpv6"] = args ? args.sshCidrBlocksIpv6 : undefined;
            resourceInputs["sshKeyName"] = args ? args.sshKeyName : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["tags"] = args ? args.tags : undefined;
            resourceInputs["updateRouteTables"] = args ? args.updateRouteTables : undefined;
            resourceInputs["useCloudwatchAgent"] = args ? args.useCloudwatchAgent : undefined;
            resourceInputs["useDefaultSecurityGroup"] = args ? args.useDefaultSecurityGroup : undefined;
            resourceInputs["useSpotInstances"] = args ? args.useSpotInstances : undefined;
            resourceInputs["useSsh"] = args ? args.useSsh : undefined;
            resourceInputs["vpcId"] = args ? args.vpcId : undefined;
            resourceInputs["autoScalingGroupArn"] = undefined /*out*/;
            resourceInputs["iamInstanceProfileArn"] = undefined /*out*/;
            resourceInputs["iamRoleArn"] = undefined /*out*/;
            resourceInputs["instanceId"] = undefined /*out*/;
            resourceInputs["networkInterfaceId"] = undefined /*out*/;
            resourceInputs["privateIp"] = undefined /*out*/;
            resourceInputs["publicDns"] = undefined /*out*/;
            resourceInputs["publicIp"] = undefined /*out*/;
            resourceInputs["securityGroupId"] = undefined /*out*/;
        } else {
            resourceInputs["autoScalingGroupArn"] = undefined /*out*/;
            resourceInputs["iamInstanceProfileArn"] = undefined /*out*/;
            resourceInputs["iamRoleArn"] = undefined /*out*/;
            resourceInputs["instanceId"] = undefined /*out*/;
            resourceInputs["networkInterfaceId"] = undefined /*out*/;
            resourceInputs["privateIp"] = undefined /*out*/;
            resourceInputs["publicDns"] = undefined /*out*/;
            resourceInputs["publicIp"] = undefined /*out*/;
            resourceInputs["securityGroupId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FckNat.__pulumiType, name, resourceInputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a FckNat resource.
 */
export interface FckNatArgs {
    additionalSecurityGroupIds?: pulumi.Input<string[]>;
    amiId?: pulumi.Input<string>;
    attachSsmPolicy?: pulumi.Input<boolean>;
    cloudwatchAgentConfigurationArnParam?: pulumi.Input<string>;
    cloudwatchAgentConfigurationCollectionInterval?: pulumi.Input<number>;
    cloudwatchAgentConfigurationEndpointOverride?: pulumi.Input<string>;
    cloudwatchAgentConfigurationNamespace?: pulumi.Input<string>;
    ebsRootVolumeSize?: pulumi.Input<number>;
    eipAllocationIds?: pulumi.Input<string[]>;
    encryption?: pulumi.Input<boolean>;
    haMode?: pulumi.Input<boolean>;
    instanceType?: pulumi.Input<string>;
    kmsKeyId?: pulumi.Input<string>;
    name: pulumi.Input<string>;
    routeTableIds?: pulumi.Input<{[key: string]: any}>;
    sshCidrBlocksIpv4?: pulumi.Input<string[]>;
    sshCidrBlocksIpv6?: pulumi.Input<string[]>;
    sshKeyName?: pulumi.Input<string>;
    subnetId: pulumi.Input<string>;
    tags?: pulumi.Input<{[key: string]: any}>;
    updateRouteTables?: pulumi.Input<boolean>;
    useCloudwatchAgent?: pulumi.Input<boolean>;
    useDefaultSecurityGroup?: pulumi.Input<boolean>;
    useSpotInstances?: pulumi.Input<boolean>;
    useSsh?: pulumi.Input<boolean>;
    vpcId: pulumi.Input<string>;
}
