// *** WARNING: this file was generated by pulumi. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Fcknat.Gateway
{
    [FcknatResourceType("fcknat:Gateway:FckNat")]
    public partial class FckNat : global::Pulumi.ComponentResource
    {
        [Output("autoScalingGroupArn")]
        public Output<string> AutoScalingGroupArn { get; private set; } = null!;

        [Output("iamInstanceProfileArn")]
        public Output<string> IamInstanceProfileArn { get; private set; } = null!;

        [Output("iamRoleArn")]
        public Output<string> IamRoleArn { get; private set; } = null!;

        [Output("instanceId")]
        public Output<string> InstanceId { get; private set; } = null!;

        [Output("networkInterfaceId")]
        public Output<string> NetworkInterfaceId { get; private set; } = null!;

        [Output("privateIp")]
        public Output<string> PrivateIp { get; private set; } = null!;

        [Output("publicDns")]
        public Output<string> PublicDns { get; private set; } = null!;

        [Output("publicIp")]
        public Output<string> PublicIp { get; private set; } = null!;

        [Output("securityGroupId")]
        public Output<string> SecurityGroupId { get; private set; } = null!;


        /// <summary>
        /// Create a FckNat resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public FckNat(string name, FckNatArgs args, ComponentResourceOptions? options = null)
            : base("fcknat:Gateway:FckNat", name, args ?? new FckNatArgs(), MakeResourceOptions(options, ""), remote: true)
        {
        }

        private static ComponentResourceOptions MakeResourceOptions(ComponentResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new ComponentResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = ComponentResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class FckNatArgs : global::Pulumi.ResourceArgs
    {
        [Input("additionalSecurityGroupIds")]
        private InputList<string>? _additionalSecurityGroupIds;
        public InputList<string> AdditionalSecurityGroupIds
        {
            get => _additionalSecurityGroupIds ?? (_additionalSecurityGroupIds = new InputList<string>());
            set => _additionalSecurityGroupIds = value;
        }

        [Input("amiId")]
        public Input<string>? AmiId { get; set; }

        [Input("attachSsmPolicy")]
        public Input<bool>? AttachSsmPolicy { get; set; }

        [Input("cloudwatchAgentConfigurationArnParam")]
        public Input<string>? CloudwatchAgentConfigurationArnParam { get; set; }

        [Input("cloudwatchAgentConfigurationCollectionInterval")]
        public Input<int>? CloudwatchAgentConfigurationCollectionInterval { get; set; }

        [Input("cloudwatchAgentConfigurationEndpointOverride")]
        public Input<string>? CloudwatchAgentConfigurationEndpointOverride { get; set; }

        [Input("cloudwatchAgentConfigurationNamespace")]
        public Input<string>? CloudwatchAgentConfigurationNamespace { get; set; }

        [Input("ebsRootVolumeSize")]
        public Input<int>? EbsRootVolumeSize { get; set; }

        [Input("eipAllocationIds")]
        private InputList<string>? _eipAllocationIds;
        public InputList<string> EipAllocationIds
        {
            get => _eipAllocationIds ?? (_eipAllocationIds = new InputList<string>());
            set => _eipAllocationIds = value;
        }

        [Input("encryption")]
        public Input<bool>? Encryption { get; set; }

        [Input("haMode")]
        public Input<bool>? HaMode { get; set; }

        [Input("instanceType")]
        public Input<string>? InstanceType { get; set; }

        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("routeTableIds")]
        private InputMap<object>? _routeTableIds;
        public InputMap<object> RouteTableIds
        {
            get => _routeTableIds ?? (_routeTableIds = new InputMap<object>());
            set => _routeTableIds = value;
        }

        [Input("sshCidrBlocksIpv4")]
        private InputList<string>? _sshCidrBlocksIpv4;
        public InputList<string> SshCidrBlocksIpv4
        {
            get => _sshCidrBlocksIpv4 ?? (_sshCidrBlocksIpv4 = new InputList<string>());
            set => _sshCidrBlocksIpv4 = value;
        }

        [Input("sshCidrBlocksIpv6")]
        private InputList<string>? _sshCidrBlocksIpv6;
        public InputList<string> SshCidrBlocksIpv6
        {
            get => _sshCidrBlocksIpv6 ?? (_sshCidrBlocksIpv6 = new InputList<string>());
            set => _sshCidrBlocksIpv6 = value;
        }

        [Input("sshKeyName")]
        public Input<string>? SshKeyName { get; set; }

        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        [Input("tags")]
        private InputMap<object>? _tags;
        public InputMap<object> Tags
        {
            get => _tags ?? (_tags = new InputMap<object>());
            set => _tags = value;
        }

        [Input("updateRouteTables")]
        public Input<bool>? UpdateRouteTables { get; set; }

        [Input("useCloudwatchAgent")]
        public Input<bool>? UseCloudwatchAgent { get; set; }

        [Input("useDefaultSecurityGroup")]
        public Input<bool>? UseDefaultSecurityGroup { get; set; }

        [Input("useSpotInstances")]
        public Input<bool>? UseSpotInstances { get; set; }

        [Input("useSsh")]
        public Input<bool>? UseSsh { get; set; }

        [Input("vpcId", required: true)]
        public Input<string> VpcId { get; set; } = null!;

        public FckNatArgs()
        {
        }
        public static new FckNatArgs Empty => new FckNatArgs();
    }
}
