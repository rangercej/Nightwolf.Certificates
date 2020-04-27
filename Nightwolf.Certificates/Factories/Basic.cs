namespace Nightwolf.Certificates.Factories
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate static factory methods to quickly build certificates
    /// </summary>
    /// <remarks>
    /// These methods construct basic certificates with minimum requirements
    /// for a CA, SubCA and subject.
    /// </remarks>
    public static class Basic
    {
        /// <summary>
        /// Key requirements are defined at BR sec 6.1.5
        /// </summary>
        private static readonly ECCurve DefaultCurve = ECCurve.NamedCurves.nistP384;
        private static readonly HashAlgorithmName DefaultHashAlgo = HashAlgorithmName.SHA256;

        /// <summary>Key usage flags template for CA certs</summary>
        private static readonly X509KeyUsageFlags CaKeyUsage = X509KeyUsageFlags.CrlSign
                                                       | X509KeyUsageFlags.KeyCertSign
                                                       | X509KeyUsageFlags.DigitalSignature;

        /// <summary>
        /// Construct a CAB forum compliant CA certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <returns>CA certificate request template</returns>
        public static Generator CreateCaTemplate(string subject, DateTime notBefore, DateTime notAfter)
        {
            var builder = new Generator(subject, DefaultCurve, DefaultHashAlgo);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetBasicConstraints(new X509BasicConstraintsExtension(true, false, 0, true));
            builder.SetKeyUsage(CaKeyUsage);

            return builder;
        }

        /// <summary>
        /// Construct a CAB forum compliant sub-CA certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="keyUsages">Additional key usages to apply to the sub-ca certificate</param>
        /// <returns>Sub-CA certificate request template</returns>
        public static Generator CreateSubCaTemplate(string subject, DateTime notBefore, DateTime notAfter, IEnumerable<Oid> keyUsages = null)
        {
            var builder = new Generator(subject, DefaultCurve, DefaultHashAlgo);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            builder.SetKeyUsage(CaKeyUsage);

            if (keyUsages != null)
            {
                foreach (var oiduse in keyUsages)
                {
                    builder.AddExtendedUsage(oiduse);
                }
            }

            return builder;
        }

        /// <summary>
        /// Construct a basic subscriber certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="keyUsages">Key usages to apply to the sub-ca certificate</param>
        /// <returns>Generated CA certificate object</returns>
        public static Generator CreateSubscriberTemplate(string subject, DateTime notBefore, DateTime notAfter, IEnumerable<Oid> keyUsages)
        {
            var builder = new Generator(subject, DefaultCurve, DefaultHashAlgo);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetBasicConstraints(new X509BasicConstraintsExtension(false, true, 0, true));
            builder.SetKeyUsage(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);

            foreach (var oiduse in keyUsages)
            {
                builder.AddExtendedUsage(oiduse);
            }

            return builder;
        }
    }
}
