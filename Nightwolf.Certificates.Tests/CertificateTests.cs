namespace Nightwolf.Certificates.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Nightwolf.Certificates.NamedOids;

    [TestClass]
    public class CertificateTests
    {
        [TestMethod]
        public void OidExtensionMatchesOid()
        {
            var a = new Oid("1.2.3.4.5.6.7");
            var b = new Oid("1.2.3.4.5.6.7");
            var c = new Oid("1.2.3.4.5.6.7.8");

            Assert.IsTrue(a.Matches(b));
            Assert.IsFalse(a.Matches(c));
            Assert.IsFalse(b.Matches(c));
        }

        [TestMethod]
        public void OidExtensionMatchesString()
        {
            var a = new Oid("1.2.3.4.5.6.7");

            Assert.IsTrue(a.Matches("1.2.3.4.5.6.7"));
            Assert.IsFalse(a.Matches("1.2.3.4.5.6.7.8"));
        }

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

            var chainIsValid = this.ValidateChain(subject, rootCert);

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
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
            Assert.IsTrue(rootCert.PublicKey.Oid.Matches(KeyAlgorithm.RsaEncryption));
            Assert.IsTrue(((RSA)rootCert.PublicKey.Key).KeySize == 2048);

            var subjectCert = new Generator("CN=Test subject", 4096, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            var chainIsValid = this.ValidateChain(subject, rootCert);

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.PublicKey.Oid.Matches(KeyAlgorithm.RsaEncryption));
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
            Assert.IsTrue(rootCert.PublicKey.Oid.Matches(KeyAlgorithm.IdEcPublicKey));
            Assert.IsTrue(rootCert.GetECDsaPublicKey().KeySize == 384);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);

            var subjectCert = new Generator("CN=Test subject", ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            var chainIsValid = this.ValidateChain(subject, rootCert);

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.PublicKey.Oid.Matches(KeyAlgorithm.IdEcPublicKey));
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
            Assert.IsTrue(rootCert.PublicKey.Oid.Matches(KeyAlgorithm.IdEcPublicKey));
            Assert.IsTrue(rootCert.GetECDsaPublicKey().KeySize == 384);
            Assert.IsTrue(rootCert.Issuer == rootCert.Subject);

            var subjectCert = new Generator("CN=Test subject", 4096, HashAlgorithmName.SHA256);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            var chainIsValid = this.ValidateChain(subject, rootCert);

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.PublicKey.Oid.Matches(KeyAlgorithm.RsaEncryption));
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
            Assert.IsTrue(rootCert.PublicKey.Oid.Matches(KeyAlgorithm.RsaEncryption));
            Assert.IsTrue(rootCert.GetRSAPublicKey().KeySize == 2048);

            var subjectCert = new Generator("CN=Test subject", ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
            subjectCert.SetValidityPeriod(startDate, endDate);
            var subject = subjectCert.Generate(rootCert);

            var chainIsValid = this.ValidateChain(subject, rootCert);

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(subject.NotBefore == startDate);
            Assert.IsTrue(subject.NotAfter == endDate);
            Assert.IsTrue(subject.HasPrivateKey);
            Assert.IsTrue(subject.PublicKey.Oid.Matches(KeyAlgorithm.IdEcPublicKey));
            Assert.IsTrue(subject.GetECDsaPublicKey().KeySize == 521);
        }

        [TestMethod]
        public void GenericFactory()
        {
            var startDate = DateTime.Now;
            var endDate = startDate.AddDays(1);
            var ca = Factories.Basic.CreateCaTemplate("CN=Test Root", startDate, endDate);
            var subca = Factories.Basic.CreateSubCaTemplate("CN=Test SubCA", startDate, endDate);
            var subject = Factories.Basic.CreateSubscriberTemplate("CN=Test Subject", startDate, endDate, new[] { NamedOids.CertificateUses.IdKpClientAuth, NamedOids.CertificateUses.IdKpServerAuth });

            var certCa = ca.Generate();
            var certSubCa = subca.Generate(certCa);
            var certSubject = subject.Generate(certSubCa);

            var chainIsValid = this.ValidateChain(certSubject, certSubCa, certCa);

            var basicConstraintCa = certCa.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;
            var basicConstraintSubCa = certSubCa.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;
            var basicConstraintSubject = certSubject.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(basicConstraintCa.CertificateAuthority);
            Assert.IsTrue(basicConstraintSubCa.CertificateAuthority);
            Assert.IsFalse(basicConstraintSubject.CertificateAuthority);
        }

        [TestMethod]
        public void CabForumFactory()
        {
            var startDate = DateTime.Now;
            var endDate = startDate.AddDays(1);
            var ca = Factories.CabForum.CreateCaTemplate("CN=Test Root", startDate, endDate);
            var subca = Factories.CabForum.CreateSubCaTemplate("CN=Test SubCA", startDate, endDate, new Uri("http://localhost/invalid"), "Test CA", new Uri("http://localhost/invalid"));
            var subject = Factories.CabForum.CreateSubscriberTemplate("CN=Test Subject", startDate, endDate, new Uri("http://localhost/invalid"), "Test CA", new Uri("http://localhost/invalid"));

            var certCa = ca.Generate();
            var certSubCa = subca.Generate(certCa);
            var certSubject = subject.Generate(certSubCa);

            var chainIsValid = this.ValidateChain(certSubject, certSubCa, certCa);

            var basicConstraintCa = certCa.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;
            var basicConstraintSubCa = certSubCa.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;
            var basicConstraintSubject = certSubject.Extensions.Cast<X509Extension>().Where(ext => ext.Oid.Matches(CertificateExtensions.IdCeBasicConstraints)).FirstOrDefault() as X509BasicConstraintsExtension;

            Assert.IsTrue(chainIsValid);
            Assert.IsTrue(basicConstraintCa.CertificateAuthority);
            Assert.IsTrue(basicConstraintSubCa.CertificateAuthority);
            Assert.IsFalse(basicConstraintSubject.CertificateAuthority);
        }

        private bool ValidateChain(X509Certificate2 subscriberCert, params X509Certificate2[] issuingCerts)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            foreach (var cert in issuingCerts)
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }

            var chainIsValid = chain.Build(subscriberCert);
            return chainIsValid;
        }
    }
}
