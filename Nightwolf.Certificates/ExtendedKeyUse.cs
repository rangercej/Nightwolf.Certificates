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
        public static readonly Oid ServerAuth = NamedOids.IdKpServerAuth;

        /// <summary>OID for Client Authentication use</summary>
        public static readonly Oid ClientAuth = NamedOids.IdKpClientAuth;

        /// <summary>OID for Code Signing use</summary>
        public static readonly Oid CodeSigning = NamedOids.IdKpCodeSigning;

        /// <summary>OID for email protection use</summary>
        public static readonly Oid EmailProtection = NamedOids.IdKpEmailProtection;

        /// <summary>OID for timestamping use</summary>
        public static readonly Oid TimeStamping = NamedOids.IdKpTimeStamping;

        /// <summary>OID for OCSP signing use</summary>
        public static readonly Oid OcspSigning = NamedOids.IdKpOcspSigning;

        /// <summary>OID for Smartcard Login use</summary>
        public static readonly Oid SmartcardLogin = NamedOids.XcnOidKpSmartcardLogon;
    }
}
