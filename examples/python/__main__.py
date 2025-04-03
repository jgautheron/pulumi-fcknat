import pulumi
import pulumi_fcknat as fcknat

my_fck_nat = fcknat.FckNat("myFckNat",
    name="example-fcknat",
    vpc_id="vpc-12345678",
    subnet_id="subnet-12345678",
    instance_type="t4g.nano",
    ha_mode=False,
    use_spot_instances=True,
    use_ssh=False,
    encryption=True,
    update_route_tables=True,
    attach_ssm_policy=True,
    tags={
        "Environment": "dev",
        "ManagedBy": "pulumi",
    })
pulumi.export("securityGroupId", {
    "value": my_fck_nat.security_group_id,
})
pulumi.export("instanceId", {
    "value": my_fck_nat.instance_id,
})
pulumi.export("publicIp", {
    "value": my_fck_nat.public_ip,
})
