namespace Nightwolf.Certificates
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    ///  Certificate generator
    /// </summary>
    public sealed class Generator
    {
        /// <summary>Certificate builder</summary>
        private readonly CertificateRequest certReq;

        /// <summary>Certificate start date and time</summary>
        private DateTime? startDateTime;

        /// <summary>Certificate end date and time</summary>
        private DateTime? endDateTime;

        /// <summary>Certificate alternate names</summary>
        private SubjectAlternativeNameBuilder sanBuilder;

        /// <summary>Extended key uses</summary>
        private readonly OidCollection extendedUses = new OidCollection();

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
            this.AddSubjectAltName(subject);
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
            this.AddSubjectAltName(subject);
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
        /// Set the nsComment extension text
        /// </summary>
        /// <param name="comment">Comment text</param>
        public void SetComment(string comment)
        {
            var oid = new Oid("2.16.840.1.113730.1.13");

            if (this.certReq.CertificateExtensions.Count(x => x.Oid.Value == oid.Value) != 0)
            {
                throw new ArgumentException("Comment already set");
            }

            // var str = comment.To
            // var extension = new X509Extension(oid, Encoding.UTF8.GetBytes(comment), false);
            // this.certReq.CertificateExtensions.Add(extension);
        }

        /// <summary>
        /// Set the appropriate parts for a CA authority
        /// </summary>
        public void SetCertAsCa()
        {
            this.certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            var useFlags = X509KeyUsageFlags.CrlSign 
                            | X509KeyUsageFlags.KeyCertSign
                            | X509KeyUsageFlags.DigitalSignature;
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
        /// <returns>X509 certificate</returns>
        public X509Certificate2 Generate()
        {
            if (this.startDateTime == null)
            {
                throw new ArgumentNullException(nameof(this.startDateTime));
            }

            if (this.endDateTime == null)
            {
                throw new ArgumentNullException(nameof(this.endDateTime));
            }

            this.certReq.CertificateExtensions.Add(this.sanBuilder.Build());
            if (this.extendedUses.Count > 0)
            {
                this.certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(this.extendedUses, false));
            }

            var cert = this.certReq.CreateSelfSigned(this.startDateTime.Value, this.endDateTime.Value);
            return cert;
        }
    }
}
