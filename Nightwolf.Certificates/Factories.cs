using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using Nightwolf.DerEncoder;

namespace Nightwolf.Certificates
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    /// <summary>
    /// Certificate static factory methods to quickly build certificates
    /// </summary>
    /// <remarks>
    /// Based on BR 1.6.2 <see cref="https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.6.2.pdf"/>
    /// </remarks>
    public static class Factories
    {
        /// <summary>
        /// Key requirements are defined at BR sec 6.1.5
        /// </summary>
        private static readonly ECCurve DefaultCurve = ECCurve.NamedCurves.nistP384;
        private static readonly HashAlgorithmName DefaultHashAlgo = HashAlgorithmName.SHA256;

        /// <summary>Key usage flags template for CA certs</summary>
        public static readonly X509KeyUsageFlags CaKeyUsage = X509KeyUsageFlags.CrlSign
                                                       | X509KeyUsageFlags.KeyCertSign
                                                       | X509KeyUsageFlags.DigitalSignature;

        /// <summary>
        /// Construct a CAB forum compliant CA certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <returns>CA certificate request template</returns>
        /// <remarks>CAB BR 7.1.2.1</remarks>
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
        /// <param name="crlDistributionPoint">URL of RFC 5280-compliant certificate revocation list</param>
        /// <param name="certPolicyStatement">Brief certificate policy statement (200 chars max)</param>
        /// <param name="keyUsages">Additional key usages to apply to the sub-ca certificate</param>
        /// <returns>Sub-CA certificate request template</returns>
        /// <remarks>CAB BR 7.2.2.2</remarks>
        public static Generator CreateSubCaTemplate(string subject, DateTime notBefore, DateTime notAfter, Uri crlDistributionPoint, string certPolicyStatement = null, Uri certPolicyUrl = null, IEnumerable<Oid> keyUsages = null)
        {
            if (certPolicyStatement != null && certPolicyStatement.Length > 200)
            {
                // RFC 5280, sec 4.2.1.4
                throw new ArgumentException("Policy too long", nameof(certPolicyStatement));
            }

            var builder = new Generator(subject, DefaultCurve, DefaultHashAlgo);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetBasicConstraints(new X509BasicConstraintsExtension(true, true, 1, true));
            builder.SetKeyUsage(CaKeyUsage);
            builder.SetCrlDistributionPoint(crlDistributionPoint);
            builder.SetCertificatePolicy(certPolicyStatement, certPolicyUrl);
            builder.SetAuthorityInformationAccess(crlDistributionPoint);
            builder.AddExtendedUsage(ExtendedKeyUses.ClientAuth);
            builder.AddExtendedUsage(ExtendedKeyUses.ServerAuth);

            if (keyUsages != null)
            {
                foreach (var oiduse in keyUsages.Where(x => x.Value != ExtendedKeyUses.ServerAuth.Value && x.Value != ExtendedKeyUses.ClientAuth.Value))
                {
                    builder.AddExtendedUsage(oiduse);
                }
            }

            return builder;
        }

        /// <summary>
        /// Construct a CAB forum compliant subscriber certificate
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="notBefore">Not valid before</param>
        /// <param name="notAfter">Not valid after</param>
        /// <param name="crlDistributionPoint">URL of RFC 5280-compliant certificate revocation list</param>
        /// <param name="certPolicyStatement">Brief certificate policy statement (200 chars max)</param>
        /// <param name="keyUsages">Additional key usages to apply to the sub-ca certificate</param>
        /// <returns>Generated CA certificate object</returns>
        /// <remarks>CAB BR 7.1.2.2</remarks>
        public static Generator CreateSubscriberTemplate(string subject, DateTime notBefore, DateTime notAfter, Uri crlDistributionPoint = null, string certPolicyStatement = null, Uri certPolicyUrl = null, IEnumerable<Oid> keyUsages = null)
        {
            if (certPolicyStatement != null && certPolicyStatement.Length > 200)
            {
                // RFC 5280, sec 4.2.1.4
                throw new ArgumentException("Policy too long", nameof(certPolicyStatement));
            }

            var builder = new Generator(subject, DefaultCurve, DefaultHashAlgo);
            builder.SetValidityPeriod(notBefore, notAfter);
            builder.SetBasicConstraints(new X509BasicConstraintsExtension(false, true, 0, true));
            builder.SetKeyUsage(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
            if (crlDistributionPoint != null)
            {
                builder.SetCrlDistributionPoint(crlDistributionPoint);
            }

            builder.SetCertificatePolicy(certPolicyStatement, certPolicyUrl);
            builder.SetAuthorityInformationAccess(crlDistributionPoint);
            builder.AddExtendedUsage(ExtendedKeyUses.ClientAuth);
            builder.AddExtendedUsage(ExtendedKeyUses.ServerAuth);

            if (keyUsages != null)
            {
                foreach (var oiduse in keyUsages.Where(x => x.Value != ExtendedKeyUses.ServerAuth.Value && x.Value != ExtendedKeyUses.ClientAuth.Value))
                {
                    builder.AddExtendedUsage(oiduse);
                }
            }

            return builder;
        }

    }
}
