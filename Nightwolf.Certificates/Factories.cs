namespace Nightwolf.Certificates
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate static factory methods to quickly build certificates
    /// </summary>
    public static class Factories
    {
        /// <summary>
        /// Construct a CAB forum compliant CA certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <returns>Generated CA certificate object</returns>
        public static X509Certificate2 BuildCaCertificate(string subject, DateTime notBefore, DateTime notAfter)
        {
            var builder = new Generator(subject, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA256);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetCertAsCa();

            return builder.Generate();
        }

        /// <summary>
        /// Construct a CAB forum compliant subject certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="issuer">Issuing certificate</param>
        /// <returns>Generated CA certificate object</returns>
        public static X509Certificate2 BuildCaCertificate(string subject, DateTime notBefore, DateTime notAfter, X509Certificate2 issuer)
        {
            var builder = new Generator(subject, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA256);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.AddSubjectAltName(subject);

            return builder.Generate(issuer);
        }
        
        /// <summary>
        /// Construct a CAB forum compliant subject certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="issuer">Issuing certificate</param>
        /// <returns>Generated CA certificate object</returns>
        public static X509Certificate2 BuildSubCaCertificate(List<string> subject, DateTime notBefore, DateTime notAfter, X509Certificate2 issuer)
        {
            // TODO: Need to complete this.

            var primarySubject = subject[0];
            var builder = new Generator(primarySubject, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA256);
            builder.SetValidityPeriod(notBefore, notAfter);
            foreach (var s in subject)
            {
                builder.AddSubjectAltName(s);
            }

            return builder.Generate(issuer);
        }

        /// <summary>
        /// Construct a CAB forum compliant subject certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="issuer">Issuing certificate</param>
        /// <returns>Generated CA certificate object</returns>
        public static X509Certificate2 BuildSubjectCertificate(List<string> subject, DateTime notBefore, DateTime notAfter, X509Certificate2 issuer)
        {
            // TODO: Need to complete this.

            var primarySubject = subject[0];
            var builder = new Generator(primarySubject, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA256);
            builder.SetValidityPeriod(notBefore, notAfter);
            foreach (var s in subject)
            {
                builder.AddSubjectAltName(s);
            }

            return builder.Generate(issuer);
        }
    }
}
