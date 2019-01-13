namespace Nightwolf.Certificates
{
    using System.Security.Cryptography;

    /// <summary>
    /// Key usage OIDs
    /// </summary>
    /// <remarks>
    /// Source: https://docs.microsoft.com/en-us/windows/desktop/api/CertEnroll/nn-certenroll-ix509extensionenhancedkeyusage
    /// </remarks>
    public static class ExtendedKeyUses
    {
        /// <summary>OID for Server Authentication use</summary>
        public static readonly Oid ServerAuth = new Oid("1.3.6.1.5.5.7.3.1");

        /// <summary>OID for Client Authentication use</summary>
        public static readonly Oid ClientAuth = new Oid("1.3.6.1.5.5.7.3.2");

        /// <summary>OID for Code Signing use</summary>
        public static readonly Oid CodeSigning = new Oid("1.3.6.1.5.5.7.3.3");

        /// <summary>OID for Smartcard Login use</summary>
        public static readonly Oid SmartcardLogin = new Oid("1.3.6.1.4.1.311.20.2.2");
    }
}
