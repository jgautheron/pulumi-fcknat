# Pulumi fcknat Provider

This repository contains a Pulumi native provider for fcknat, an alternative to AWS NAT gateways. This provider allows you to create and manage fcknat resources in your AWS infrastructure.

## Overview

The fcknat provider implements a cost-effective alternative to AWS NAT gateways, giving you similar functionality with more flexibility and at a lower cost.

## Installing

This package is available for several languages/platforms:

- JavaScript/TypeScript: `npm install @jgautheron/fcknat`
- Python: `pip install pulumi_fcknat`
- Go: `import "github.com/jgautheron/pulumi-fcknat/sdk/go/fcknat"`
- .NET: `dotnet add package jgautheron.fcknat`

## Prerequisites

You will need to ensure the following tools are installed and present in your `$PATH`:

- [`pulumictl`](https://github.com/pulumi/pulumictl#installation)
- [Go 1.21](https://golang.org/dl/) or 1.latest
- [NodeJS](https://nodejs.org/en/) 14.x or later
- [Yarn](https://yarnpkg.com/)
- [Python](https://www.python.org/downloads/) 3.9 or later (called as `python3`)
- [.NET](https://dotnet.microsoft.com/download)

## Building the Provider

### Build and Install

Run `make build install` to build and install the provider:

```bash
$ make build install
```

This will:

1. Build the provider binary and place it in a `./bin` folder
2. Generate the Go, Node.js, Python, and .NET SDKs
3. Install the provider on your machine

For Python SDK installation, a virtual environment is automatically created to avoid conflicts with system Python packages.

### Clean Build Artifacts

To clean up build artifacts and virtual environments:

```bash
$ make clean
```

## Usage Example

Here's a simple example of using the fcknat provider to create a NAT instance:

```typescript
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as fcknat from "@jgautheron/fcknat";

// Get the default VPC and a subnet
const vpc = aws.ec2.getVpcOutput({ default: true });
const subnet = aws.ec2.getSubnetOutput({
  vpcId: vpc.id,
  defaultForAz: true,
  availabilityZone: "us-east-1a",
});

// Create a fck-nat instance
const nat = new fcknat.FckNat("my-nat", {
  name: "my-nat",
  vpcId: vpc.id,
  subnetId: subnet.id,
  // Optional parameters
  instanceType: "t4g.nano",
  haMode: true,
  useSsh: true,
  sshCidrBlocksIpv4: ["10.0.0.0/8"],
});

// Export the outputs
export const securityGroupId = nat.securityGroupId;
export const privateIp = nat.privateIp;
export const publicIp = nat.publicIp;
```

## Contributing

### Building and Testing Locally

1. Build and install the provider:

   ```bash
   $ make build install
   ```

2. Create a simple test program:
   ```bash
   $ cd examples/typescript
   $ yarn link @jgautheron/fcknat
   $ yarn install
   $ pulumi stack init test
   $ pulumi preview
   ```

### Development Workflow

1. Make changes to the provider implementation in `provider/fcknatComponent.go`
2. Build the provider with `make provider`
3. Build all SDKs with `make build`
4. Install all SDKs with `make install`
5. Test your changes with a sample program

## Notes for macOS Users

When building the Python SDK on macOS, you might encounter an "externally-managed-environment" error. The Makefile has been updated to handle this by using virtual environments for Python operations.

## References

- [fck-nat GitHub Repository](https://github.com/AndrewGuenther/fck-nat)
- [Pulumi Resource Providers](https://www.pulumi.com/docs/using-pulumi/pulumi-packages/how-to-author/)
