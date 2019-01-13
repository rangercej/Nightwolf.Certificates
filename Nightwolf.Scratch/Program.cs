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
