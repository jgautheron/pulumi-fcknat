# YAML Example Program

Test Pulumi program written in YAML for testing the fcknat provider locally.

This example creates a fcknat instance which serves as an alternative to AWS NAT gateways.

## Prerequisites

This example requires:

- AWS credentials configured
- A default VPC with a subnet in availability zone "us-east-1a" (modify as needed for your environment)

## Running the Example

```bash
pulumi login
pulumi stack init local
pulumi up
```

## Resources Created

This example will create:

- An EC2 instance serving as a NAT gateway
- A security group
- A network interface
- IAM role and instance profile
- Routes in specified route tables (if configured)

## Important Note

This example uses actual AWS resources that will incur costs. Make sure to run `pulumi destroy` when you're done to avoid unexpected charges.

The remaining examples in the `./examples` directory are language-specific examples derived from this YAML example using the `make gen_examples` command. To regenerate these examples, run `make gen_examples` in the root of this repository.
