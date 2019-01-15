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
            gen.SetCertAsCa();
            gen.AddSubjectAltName("E=bob@example.org");
            gen.AddExtendedUsage(ExtendedKeyUses.ClientAuth);
            gen.AddExtendedUsage(ExtendedKeyUses.SmartcardLogin);
            gen.AddCustomValue(new Oid("1.2.3.4.5.6.7.8.9.10"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            gen.AddCustomValue(new Oid("1.2.3.4.5.6.7.8.9.11"), "This is a really long string that's more than 127 characters long. We do this to test that the length code is doing the right thing, which it may or may not be doing. I need it to be at least 256 characters long to check the two byte length indicator in byte 1. Hopefully, this will work correctly.");
            gen.AddCustomValue(new Oid("1.2.3.4.5.6.7.8.9.12"), -34);
            gen.AddCustomValue(new Oid("1.2.3.4.5.6.7.8.9.13"), true);
            var cert = gen.Generate();
            var bytes = cert.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("cert_ec.pfx", bytes);

            // Create certificate with custom strength
            gen = new Generator("CN=example.org", 2048, HashAlgorithmName.SHA384);
            gen.SetComment("This is a comment");
            gen.SetValidityPeriod(new DateTime(2000, 1, 1), new DateTime(2010, 1, 1));
            gen.SetCertAsCa();
            cert = gen.Generate();
            bytes = cert.Export(X509ContentType.Pfx, string.Empty);
            System.IO.File.WriteAllBytes("cert_rsa.pfx", bytes);
        }
    }
}
