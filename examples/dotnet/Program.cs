using System.Collections.Generic;
using System.Linq;
using Pulumi;
using Fcknat = Pulumi.Fcknat;

return await Deployment.RunAsync(() => 
{
    var myFckNat = new Fcknat.FckNat("myFckNat", new()
    {
        Name = "example-fcknat",
        VpcId = "vpc-12345678",
        SubnetId = "subnet-12345678",
        InstanceType = "t4g.nano",
        HaMode = false,
        UseSpotInstances = true,
        UseSsh = false,
        Encryption = true,
        UpdateRouteTables = true,
        AttachSsmPolicy = true,
        Tags = 
        {
            { "Environment", "dev" },
            { "ManagedBy", "pulumi" },
        },
    });

    return new Dictionary<string, object?>
    {
        ["securityGroupId"] = 
        {
            { "value", myFckNat.SecurityGroupId },
        },
        ["instanceId"] = 
        {
            { "value", myFckNat.InstanceId },
        },
        ["publicIp"] = 
        {
            { "value", myFckNat.PublicIp },
        },
    };
});

