using System.Diagnostics;
using System.Linq;
using System.Text;
using Nightwolf.DerEncoder;

namespace Nightwolf.Scratch
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    using Nightwolf.Certificates;

    public class Program
    {
        static void Main(string[] args)
        {
            // Create certificate with default strength
            var gen = new Generator("CN=example.org");
            gen.SetComment("This is a comment");
            gen.SetValidityPeriod(new DateTime(2000, 1, 1), new DateTime(2010, 1, 1));
            //gen.SetCertAsCa();
            //gen.SetCertAsCa();
            gen.AddSubjectAltName("E=bob@example.org");
            gen.AddExtendedUsage(ExtendedKeyUses.ClientAuth);
            gen.AddExtendedUsage(ExtendedKeyUses.SmartcardLogin);
            gen.SetCustomValue(new Oid("1.2.3.4.5.6.7.8.9.10"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            gen.SetCustomValue(new Oid("1.2.3.4.5.6.7.8.9.11"), "This is a really long string that's more than 127 characters long. We do this to test that the length code is doing the right thing, which it may or may not be doing. I need it to be at least 256 characters long to check the two byte length indicator in byte 1. Hopefully, this will work correctly.");
            gen.SetCustomValue(new Oid("1.2.3.4.5.6.7.8.9.12"), -34);
            gen.SetCustomValue(new Oid("1.2.3.4.5.6.7.8.9.13"), true);
            var cert = gen.Generate();
            var bytes = cert.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("cert_ec.pfx", bytes);

            // Create certificate with custom strength
            gen = new Generator("CN=example.org", 2048, HashAlgorithmName.SHA384);
            gen.SetComment("This is a comment");
            gen.SetValidityPeriod(new DateTime(2000, 1, 1), new DateTime(2010, 1, 1));
            //gen.SetCertAsCa();
            cert = gen.Generate();
            bytes = cert.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("cert_rsa.pfx", bytes);

            var rootca = Factories.CreateCaTemplate("CN=Nightfox Test CA", new DateTime(2000, 1, 1), new DateTime(2020, 1, 1));
            var subca = Factories.CreateSubCaTemplate("CN=Nightfox Test SubCA",
                new DateTime(2000, 1, 1), 
                new DateTime(2020, 1, 1),
                new Uri("http://www.nightfox.org.uk/crls"),
                "This is a rabbit", 
                new Uri("http://www.nightfox.org.uk/"));

            var certca = rootca.Generate();
            var certsubca = subca.Generate(certca);

            bytes = certca.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("nightfoxroot.pfx", bytes);

            bytes = certsubca.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("nightfoxsubca.pfx", bytes);

            var seq = new X690Sequence(
                new X690Utf8String("Hello"),
                new X690Integer(-63461),
                new X690Oid(new Oid("2.999.3.4.5.6.7.8.9.10")),
                new X690Sequence(
                    new X690Boolean(false),
                    new X690Boolean(true),
                    new X690Utf8String("And this is the end of the world like a cat doing maths in a storm with a teacup in it's paw waiting for the end of the world caused by a dog chewing a toy bone."))
            );

            var ba = seq.GetBytes();
            var s = string.Join(" ", ba.Select(x => x.ToString("x2")));
            Debug.Print(s);
        }
    }
}
