# CertificateGenerator [![Build Status](https://travis-ci.org/rangercej/CertificateGenerator.svg?branch=master)](https://travis-ci.org/rangercej/CertificateGenerator)

This project contains two parts:

* `Nightwolf.Certificates` - A wrapper around .NET's new CertificateRequest object to ease the creation of certificates. Provides a useable alternative to BouncyCastle.

* `Nightwolf.DerEncoder` - ITU X.690 DER encoder, easing the creation of ASN.1 encoding for certificate extensions.

## Prerequisites

System.Security.Cryptography.X509Certificates.CertificateRequest is a new
object in .NET 4.7.2 and .Net Core 2.0.

The solution was developed with Visual Studio 2017 Community Edition. Testing
a build with .NET Core is planned but not yet complete.

## Using

There are two ways of using this:
* The static factory methods in `Nightwolf.Certificates.Factories`
* Manually building up from an empty certificate

### Factory Methods (Nightwolf.Certificates.Factories)

There are three methods that are intended to create CAB-compliant certificates.
The CAB is the CA-Browser Forum, and are the body that define the requirements
for root, intermediate, and subscriber certificates that are used on the
public internet.

The methods available are:
* `CreateCaTemplate` - creates a certificate template for a root CA certificate
* `CreateSubCaTemplate` - creates a certificate template for a sub-CA certificate
* `CreateSubscriberTemplate` - creates the end-user subscriber certificate

In all three cases, they return an instance of `Nightwolf.Certificates.Generator`,
allowing the template to be modified further before generation.

### Nightwolf.Certificates.Generator

All the methods in this class ease the addition of adding X509 extensions to
a certificate by abstracting away the encoding of data to ASN.1 DER encoded
bytes.

For example:
```
var gen = new Generator("CN=example.org");
gen.SetComment("This is a comment");
gen.SetValidityPeriod(new DateTime(2000, 1, 1), new DateTime(2010, 1, 1));
gen.AddSubjectAltName("E=bob@example.org");
gen.AddExtendedUsage(ExtendedKeyUses.ClientAuth);
gen.AddExtendedUsage(ExtendedKeyUses.SmartcardLogin);
gen.SetCustomValue(new Oid("1.2.3.4.5.6.7.8.9.10"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

// Create a self-signed certificate
var selfcert = gen.Generate()

// Create a certificate signed by an authority. The "parent" parameter is
// an X509Certificate2 complete with private key.
var cert = gen.Generator(parent);
```

### Helper class: Nightwolf.Certificates.DerEncoder

This cla ss provides a fast-forward DER-encoder as defined by ITU X.690 for a
number of ASN.1 datatypes.

For example:

```
var seq = new X690Sequence(
    new X690Utf8String("Hello"),
    new X690Integer(-63461),
    new X690Oid(new Oid("2.999.3.4.5.6.7.8.9.10")),
    new X690Sequence(
        new X690Boolean(false),
        new X690Boolean(true),
        new X690Utf8String("And this is the end of the world like a cat doing maths in a storm with a teacup in it's paw waiting for the end of the world caused by a dog chewing a toy bone."))
);
```

## Authors
* ** Chris Johnson** - [rangercej](https://github.com/rangercej)
