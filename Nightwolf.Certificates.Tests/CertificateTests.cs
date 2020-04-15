namespace Nightwolf.Certificates.Tests
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CertificateTests
    {
        [TestMethod]
        public void SelfsignedCert()
        {
            var startDate = new DateTime(2000, 1, 1);
            var endDate = new DateTime(2010, 1, 1);

            var gen = new Generator("CN=example.org");
            gen.SetValidityPeriod(startDate, endDate);
            var cert = gen.Generate();

            Assert.IsTrue(cert.NotBefore == startDate);
            Assert.IsTrue(cert.NotAfter == endDate);
            Assert.IsTrue(cert.HasPrivateKey);
            Assert.IsTrue(cert.Issuer == cert.Subject);
        }

        [TestMethod]
        public void ChainedCertDefaultAlgo()
        {
            var startDate = new DateTime(2015, 1, 1);
            var endDate = new DateTime(2035, 1, 1);

            var rootCa = new Generator("CN=Test Root CA");
            rootCa.SetValidityPeriod(startDate, endDate);
            rootCa.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            var rootCert = rootCa.Generate();

            Assert.IsTrue(rootCert.NotBefore == startDate);
            Assert.IsTrue(rootCert.NotAfter == endDate);
            Assert.IsTrue(rootCert.HasPrivateKey);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);

            var subjectCert = new Generator("CN=Test subject");
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.Issuer == rootCert.Subject);
        }

        [TestMethod]
        public void ChainedCertRsaAlgo()
        {
            var startDate = new DateTime(2015, 1, 1);
            var endDate = new DateTime(2035, 1, 1);

            var rootCa = new Generator("CN=Test Root CA", 2048, HashAlgorithmName.SHA256);
            rootCa.SetValidityPeriod(startDate, endDate);
            rootCa.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            var rootCert = rootCa.Generate();

            Assert.IsTrue(rootCert.NotBefore == startDate);
            Assert.IsTrue(rootCert.NotAfter == endDate);
            Assert.IsTrue(rootCert.HasPrivateKey);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);
            Assert.IsTrue(rootCert.PublicKey.Oid.Value == NamedOids.RsaEncryption.Value);
            Assert.IsTrue(((RSA)rootCert.PublicKey.Key).KeySize == 2048);

            var subjectCert = new Generator("CN=Test subject", 4096, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.Issuer == rootCert.Subject);
            Assert.IsTrue(subject.PublicKey.Oid.Value == NamedOids.RsaEncryption.Value);
            Assert.IsTrue(((RSA)subject.PublicKey.Key).KeySize == 4096);
        }
        [TestMethod]
        public void ChainedCertEcDsaAlgo()
        {
            var startDate = new DateTime(2015, 1, 1);
            var endDate = new DateTime(2035, 1, 1);

            var rootCa = new Generator("CN=Test Root CA", ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
            rootCa.SetValidityPeriod(startDate, endDate);
            rootCa.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            var rootCert = rootCa.Generate();

            Assert.IsTrue(rootCert.NotBefore == startDate);
            Assert.IsTrue(rootCert.NotAfter == endDate);
            Assert.IsTrue(rootCert.HasPrivateKey);
            Assert.IsTrue(rootCert.PublicKey.Oid.Value == NamedOids.IdEcPublicKey.Value);
            Assert.IsTrue(rootCert.GetECDsaPublicKey().KeySize == 384);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);

            var subjectCert = new Generator("CN=Test subject", ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.Issuer == rootCert.Subject);
            Assert.IsTrue(subject.PublicKey.Oid.Value == NamedOids.IdEcPublicKey.Value);
            Assert.IsTrue(subject.GetECDsaPublicKey().KeySize == 521);
        }

        [TestMethod]
        public void ChainedCertEcRootRsaSubject()
        {
            var startDate = new DateTime(2015, 1, 1);
            var endDate = new DateTime(2035, 1, 1);

            var rootCa = new Generator("CN=Test Root CA", ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
            rootCa.SetValidityPeriod(startDate, endDate);
            rootCa.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            var rootCert = rootCa.Generate();

            Assert.IsTrue(rootCert.NotBefore == startDate);
            Assert.IsTrue(rootCert.NotAfter == endDate);
            Assert.IsTrue(rootCert.HasPrivateKey);
            Assert.IsTrue(rootCert.PublicKey.Oid.Value == NamedOids.IdEcPublicKey.Value);
            Assert.IsTrue(rootCert.GetECDsaPublicKey().KeySize == 384);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);

            var subjectCert = new Generator("CN=Test subject", 4096, HashAlgorithmName.SHA256);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.Issuer == rootCert.Subject);
            Assert.IsTrue(subject.PublicKey.Oid.Value == NamedOids.RsaEncryption.Value);
            Assert.IsTrue(subject.GetRSAPublicKey().KeySize == 4096);
        }

        [TestMethod]
        public void ChainedCertRsaRootEcSubject()
        {
            var startDate = new DateTime(2015, 1, 1);
            var endDate = new DateTime(2035, 1, 1);

            var rootCa = new Generator("CN=Test Root CA", 2048, HashAlgorithmName.SHA256);
            rootCa.SetValidityPeriod(startDate, endDate);
            rootCa.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            var rootCert = rootCa.Generate();

            Assert.IsTrue(rootCert.NotBefore == startDate);
            Assert.IsTrue(rootCert.NotAfter == endDate);
            Assert.IsTrue(rootCert.HasPrivateKey);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);
            Assert.IsTrue(rootCert.PublicKey.Oid.Value == NamedOids.RsaEncryption.Value);
            Assert.IsTrue(rootCert.GetRSAPublicKey().KeySize == 2048);

            var subjectCert = new Generator("CN=Test subject", ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.Issuer == rootCert.Subject);
            Assert.IsTrue(subject.PublicKey.Oid.Value == NamedOids.IdEcPublicKey.Value);
            Assert.IsTrue(subject.GetECDsaPublicKey().KeySize == 521);
        }
    }
}
