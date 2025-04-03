import * as fcknat from "@pulumi/fcknat";

const myFckNat = new fcknat.FckNat("myFckNat", {
    name: "example-fcknat",
    vpcId: "vpc-1234567890",
    subnetId: "subnet-1234567890",
    instanceType: "t4g.nano",
    haMode: false,
    useSpotInstances: true,
    useSsh: false,
    encryption: true,
    updateRouteTables: true,
    attachSsmPolicy: true,
    tags: {
        Environment: "dev",
        ManagedBy: "pulumi",
    },
});
export const securityGroupId = {
    value: myFckNat.securityGroupId,
};
export const instanceId = {
    value: myFckNat.instanceId,
};
export const publicIp = {
    value: myFckNat.publicIp,
};
