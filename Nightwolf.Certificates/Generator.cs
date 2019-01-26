using Nightwolf.DerEncoder;

namespace Nightwolf.Certificates
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    /// <summary>
    ///  Certificate generator
    /// </summary>
    public sealed class Generator
    {
        /// <summary>Certificate builder</summary>
        private readonly CertificateRequest certReq;

        /// <summary>Extended key uses</summary>
        private readonly OidCollection extendedUses = new OidCollection();

        /// <summary>Random number generator</summary>
        private readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        /// <summary>Certificate start date and time</summary>
        private DateTime? startDateTime;

        /// <summary>Certificate end date and time</summary>
        private DateTime? endDateTime;

        /// <summary>Certificate alternate names</summary>
        private SubjectAlternativeNameBuilder sanBuilder;

        /// <summary>
        /// Initializes a new instance of the <see cref="Generator"/> class with default parameters.
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <remarks>Generates a certificate with a P-384 ECDSA key and SHA2 signature hash</remarks>
        public Generator(string subject) : this(subject, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA256)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Generator"/> class for ECDSA-key based certificates.
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="curve">Source ECDSA curve for the key-pair</param>
        /// <param name="hash">Signature hash algorithm to use</param>
        public Generator(string subject, ECCurve curve, HashAlgorithmName hash)
        {
            var key = GenerateEcKey(curve);
            this.certReq = new CertificateRequest(subject, key, hash);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Generator"/> class for RSA-key based certificates.
        /// </summary>
        /// <param name="subject">Certificate subject</param>
        /// <param name="size">Size of the RSA key-pair to generate</param>
        /// <param name="hash">Signature hash algorithm to use</param>
        public Generator(string subject, int size, HashAlgorithmName hash)
        {
            var key = GenerateRsaKey(size);
            this.certReq = new CertificateRequest(subject, key, hash, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Generate an ECDSA key from the provided curve
        /// </summary>
        /// <param name="curve">Source curve for the key</param>
        /// <returns>Generated ECDSA key</returns>
        public static ECDsa GenerateEcKey(ECCurve curve)
        {
            var key = ECDsa.Create(curve);
            return key;
        }

        /// <summary>
        /// Generate an RSA key of the provided size
        /// </summary>
        /// <param name="bits">Key size</param>
        /// <returns>Generated RSA key</returns>
        public static RSA GenerateRsaKey(int bits)
        {
            var key = RSA.Create(bits);
            return key;
        }

        /// <summary>
        /// Add a subject alternative name
        /// </summary>
        /// <param name="subj">Alternative name to add</param>
        public void AddSubjectAltName(string subj)
        {
            if (string.IsNullOrWhiteSpace(subj))
            {
                throw new ArgumentNullException(nameof(subj));
            }

            if (this.sanBuilder == null)
            {
                this.sanBuilder = new SubjectAlternativeNameBuilder();
            }

            if (subj.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase))
            {
                var s = subj.Substring(3);
                this.sanBuilder.AddDnsName(s);
                return;
            }

            if (subj.StartsWith("E=", StringComparison.InvariantCultureIgnoreCase))
            {
                var s = subj.Substring(2);
                this.sanBuilder.AddEmailAddress(s);
                return;
            }

            if (IPAddress.TryParse(subj, out var addr))
            {
                this.sanBuilder.AddIpAddress(addr);
                return;
            }

            if (Uri.IsWellFormedUriString(subj, UriKind.Absolute))
            {
                var uri = new Uri(subj);
                this.sanBuilder.AddUri(uri);
                return;
            }

            throw new ArgumentException("Cannot identify or unsupported SAN type");
        }

        /// <summary>
        /// Set certificate validity period
        /// </summary>
        /// <param name="startTimestamp">Certificate start date</param>
        /// <param name="endTimestamp">Certificate from date</param>
        public void SetValidityPeriod(DateTime startTimestamp, DateTime endTimestamp)
        {
            if (startTimestamp > endTimestamp)
            {
                throw new ArgumentOutOfRangeException(nameof(startTimestamp), "Start datetime cannot be after end datetime");
            }

            this.startDateTime = startTimestamp;
            this.endDateTime = endTimestamp;
        }

        /// <summary>
        /// Create a certificate policy extension
        /// </summary>
        /// <param name="certPolicyStatement">Freetext brief policy statement</param>
        /// <param name="certPolicyUrl">URL that points to full policy text</param>
        /// <remarks>Defined in RFC 5280, section 4.2.1.4</remarks>
        public void SetCertificatePolicy(string certPolicyStatement, Uri certPolicyUrl)
        {
            var idx = FindExtensionByOid(NamedOids.CertificatePolicy);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            DerSequence policyText = null;
            DerSequence policyUrl = null;

            if (!string.IsNullOrWhiteSpace(certPolicyStatement))
            {
                policyText = new DerSequence(
                    new DerOid(NamedOids.PolicyQualifierIdUnotice),
                    new DerSequence(
                        new DerUtf8String(certPolicyStatement)
                    )
                );
            }

            if (certPolicyUrl != null)
            {
                policyUrl = new DerSequence(
                    new DerOid(NamedOids.PolicyQualifierIdCps),
                    new DerIa5String(certPolicyUrl.AbsoluteUri)
                );
            }

            DerSequence policyStatement = null;
            if (policyUrl != null || policyText != null)
            {
                policyStatement = new DerSequence();
                if (policyUrl != null)
                {
                    policyStatement.Add(policyUrl);
                }

                if (policyText != null)
                {
                    policyStatement.Add(policyText);
                }
            }

            var policy = new DerSequence();
            if (policyStatement == null)
            {
                policy.Add(new DerSequence(
                        new DerOid(new Oid(NamedOids.CertificatePolicyAny))
                    )
                );
            }
            else
            {
                policy.Add(new DerSequence(
                        new DerOid(new Oid(NamedOids.CertificatePolicyAny)),
                        policyStatement
                    )
                );
            }

            this.SetExtension(new X509Extension(NamedOids.CertificatePolicy, policy.GetBytes(), false));
        }

        /// <summary>
        /// Set the nsComment extension text
        /// </summary>
        /// <param name="comment">Comment text</param>
        public void SetComment(string comment)
        {
            var oid = new Oid("2.16.840.1.113730.1.13");
            var idx = FindExtensionByOid(oid);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            var asnBytes = new Nightwolf.DerEncoder.DerUtf8String(comment).GetBytes();
            var extension = new X509Extension(oid, asnBytes, false);
            this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Add a custom string extension
        /// </summary>
        /// <param name="oid">OID for extension</param>
        /// <param name="comment">Comment text</param>
        public void SetCustomValue(Oid oid, string comment)
        {
            var idx = FindExtensionByOid(oid);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            var asnBytes = new DerEncoder.DerUtf8String(comment).GetBytes();
            var extension = new X509Extension(oid, asnBytes, false);
            this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Add a custom int extension
        /// </summary>
        /// <param name="oid">OID for extension</param>
        /// <param name="val">Value to include</param>
        public void SetCustomValue(Oid oid, int val)
        {
            var idx = FindExtensionByOid(oid);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            var asnBytes = new DerEncoder.DerInteger(val).GetBytes();
            var extension = new X509Extension(oid, asnBytes, false);
            this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Add a custom boolean extension
        /// </summary>
        /// <param name="oid">OID for extension</param>
        /// <param name="val">Value to include</param>
        public void SetCustomValue(Oid oid, bool val)
        {
            var idx = FindExtensionByOid(oid);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            var asnBytes = new DerEncoder.DerBoolean(val).GetBytes();
            var extension = new X509Extension(oid, asnBytes, false);
            this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Set the appropriate parts for a CA authority
        /// </summary>
        public void SetExtension(X509Extension extension)
        {
            var idx = this.FindExtensionByOid(extension.Oid);
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Set the appropriate parts for a CA authority
        /// </summary>
        public void SetBasicConstraints(X509BasicConstraintsExtension constraints)
        {
            var idx = this.FindExtension<X509BasicConstraintsExtension>();
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            this.certReq.CertificateExtensions.Add(constraints);
        }

        /// <summary>
        /// Set the appropriate parts for a CA authority
        /// </summary>
        public void SetKeyUsage(X509KeyUsageFlags useFlags)
        {
            var idx = this.FindExtension<X509KeyUsageExtension>();
            if (idx != -1)
            {
                this.certReq.CertificateExtensions.RemoveAt(idx);
            }

            this.certReq.CertificateExtensions.Add(new X509KeyUsageExtension(useFlags, true));
        }

        /// <summary>
        /// Add a new extended use to the certificate
        /// </summary>
        /// <param name="oid">Oid of use to add</param>
        public void AddExtendedUsage(Oid oid)
        {
            foreach (var o in this.extendedUses)
            {
                if (o.Value == oid.Value)
                {
                    return;
                }
            }

            this.extendedUses.Add(oid);
        }

        /// <summary>
        /// Generate the certificate
        /// </summary>
        /// <param name="issuer">Issuing authority certificate</param>
        /// <returns>X509 certificate</returns>
        public X509Certificate2 Generate(X509Certificate2 issuer = null)
        {
            if (this.startDateTime == null)
            {
                throw new ArgumentNullException(nameof(this.startDateTime));
            }

            if (this.endDateTime == null)
            {
                throw new ArgumentNullException(nameof(this.endDateTime));
            }

            if (this.sanBuilder != null)
            {
                this.certReq.CertificateExtensions.Add(this.sanBuilder.Build());
            }

            if (this.extendedUses.Count > 0)
            {
                this.certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(this.extendedUses, false));
            }

            X509Certificate2 cert;
            if (issuer == null)
            {
                cert = this.certReq.CreateSelfSigned(this.startDateTime.Value, this.endDateTime.Value);
            }
            else
            {
                var serialNumber = new byte[8];
                this.rng.GetBytes(serialNumber);
                cert = this.certReq.Create(issuer, this.startDateTime.Value, this.endDateTime.Value, serialNumber);
            }
            return cert;
        }

        /// <summary>
        /// Search for an extension in the certificate
        /// </summary>
        /// <typeparam name="T">Type of extension to search for</typeparam>
        /// <returns>Index of first occurance of extension</returns>
        private int FindExtension<T>()
        {
            for (var i = 0; i < this.certReq.CertificateExtensions.Count; i++)
            {
                var ext = this.certReq.CertificateExtensions[i];
                if (ext is T)
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>
        /// Search for an extension in the certificate
        /// </summary>
        /// <param name="oid">OID to look for</param>
        /// <returns>Index of first occurance of extension with OID</returns>
        private int FindExtensionByOid(string oid)
        {
            for (var i = 0; i < this.certReq.CertificateExtensions.Count; i++)
            {
                var ext = this.certReq.CertificateExtensions[i];
                if (ext.Oid.Value == oid)
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>
        /// Search for an extension in the certificate
        /// </summary>
        /// <param name="oid">OID to look for</param>
        /// <returns>Index of first occurance of extension with OID</returns>
        private int FindExtensionByOid(Oid oid)
        {
            return FindExtensionByOid(oid.Value);
        }
    }
}
