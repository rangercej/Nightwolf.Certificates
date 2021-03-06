# CertificateGenerator ![.NET Core](https://github.com/rangercej/Nightwolf.Certificates/workflows/.NET%20Core/badge.svg)

This project contains two parts:

* `Nightwolf.Certificates` - A wrapper around .NET's new CertificateRequest object to ease the creation of certificates. Provides a useable alternative to BouncyCastle.

* `Nightwolf.DerEncoder` - ITU X.690 DER encoder, easing the creation of ASN.1 encoding for certificate extensions.

## Prerequisites

System.Security.Cryptography.X509Certificates.CertificateRequest is a new
object in .NET 4.7.2 and .Net Core 2.0.

The solution was developed with Visual Studio 2019 Community Edition. The solution is multi-targetting on Windows for .NET Core 3.1 and .NET 4.7.2. On Linux it's only been built and tested with .NET Core 3.1 only, but there's a strong chance the .NET 4.7.2 build will work with Mono.

## Using

There are two ways of using this:
* The static factory methods in `Nightwolf.Certificates.Factories`
* Manually building up from an empty certificate

### Factory Methods (Nightwolf.Certificates.Factories)

There are two classes that each contain three methods that are intended to 
create certificate templates for root, intermediate and subscriber certificates.

One class, CabForum, endevours to create certificate templates that align to 
CAB forum certificate requirements. The CAB is the CA-Browser Forum, and are the 
body that define the requirements for all certificates that are used on the public 
internet.

The other class, Basic, creates a minimum-specified certificate for each of root,
intermediate and subscriber. As a result, the methods ask for the minimum information
required for each certificate type.

The methods available in both are:
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
