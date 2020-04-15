namespace Nightwolf.Certificates
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate private key container
    /// </summary>
    internal sealed class CertificateKey
    {
        /// <summary>ECDSA key</summary>
        private readonly ECDsa ecKey = null;

        /// <summary>RSA key</summary>
        private readonly RSA rsaKey = null;

        /// <summary>
        /// Create key container for ECDSA key
        /// </summary>
        /// <param name="key">Key to contain</param>
        internal CertificateKey(ECDsa key)
        {
            this.ecKey = key;
        }

        /// <summary>
        /// Create key container for RSA key
        /// </summary>
        /// <param name="key">Key to contain</param>
        internal CertificateKey(RSA key)
        {
            this.rsaKey = key;
        }

        /// <summary>
        /// Add the contained private key to a X509 certificate
        /// </summary>
        /// <param name="certificate">Certificate that needs the private key added</param>
        /// <returns>Combined certificate</returns>
        internal X509Certificate2 MergeIntoCertificate(X509Certificate2 certificate)
        {
            X509Certificate2 combinedCert;

            if (this.ecKey != null)
            {
                combinedCert = certificate.CopyWithPrivateKey(this.ecKey);
            }
            else
            {
                combinedCert = certificate.CopyWithPrivateKey(this.rsaKey);
            }

            return combinedCert;
        }
    }
}
