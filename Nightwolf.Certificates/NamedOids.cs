namespace Nightwolf.Certificates.NamedOids
{
    using System.Security.Cryptography;

    /// <summary>
    /// Named OIDs from RFC 5280
    /// </summary>
    /// <remarks>
    /// Names are based on the that in the RFC, so if (for example)
    /// the name in the RFC is id-ce-certificatePolicies, we turn
    /// this into the form: IdCeCertificiatePolicies.
    /// </remarks>
    public static class RootArcs
    {
        public static readonly Oid IdPkix = Helpers.ConstructOid("1.3.6.1.5.5.7");
        public static readonly Oid IdPe = Helpers.ConstructOid(IdPkix, "1");
    }

    public static class InformationAccess
    {
        public static readonly Oid IdPeAuthorityInfoAccess = Helpers.ConstructOid(RootArcs.IdPe, "1");
        public static readonly Oid IdPeSubjectInfoAccess = Helpers.ConstructOid(RootArcs.IdPe, "11");
    }

    public static class CertificateExtensions
    {
        public static readonly Oid IdCe = Helpers.ConstructOid("2.5.29");
        public static readonly Oid IdCeBasicConstraints = Helpers.ConstructOid(IdCe, "19");
        public static readonly Oid IdCeCrlDistributionPoints = Helpers.ConstructOid(IdCe, "31");
        public static readonly Oid IdCeExtKeyUsage = Helpers.ConstructOid(IdCe, "37");
    }

    public static class CertificatePolicies
    {
        public static readonly Oid IdCeCertificatePolicies = Helpers.ConstructOid(CertificateExtensions.IdCe, "32");
        public static readonly Oid AnyPolicy = Helpers.ConstructOid(CertificateExtensions.IdCe, "32.0");
    }

    public static class PolicyQualifiers
    {
        public static readonly Oid IdQt = Helpers.ConstructOid(RootArcs.IdPkix, "2");
        public static readonly Oid IdQtCps = Helpers.ConstructOid(IdQt, "1");
        public static readonly Oid IdQtUnotice = Helpers.ConstructOid(IdQt, "2");
    }
        
    public static class AccessDescriptors
    {
        public static readonly Oid IdAd = Helpers.ConstructOid(RootArcs.IdPkix, "48");
        public static readonly Oid IdAdOcsp = Helpers.ConstructOid(IdAd, "1");
        public static readonly Oid IdAdCaIssuers = Helpers.ConstructOid(IdAd, "2");
    }

    /// <summary>Certificate extended uses</summary>
    public static class CertificateUses
    {
        public static readonly Oid IdKp = Helpers.ConstructOid(RootArcs.IdPkix, "3");
        public static readonly Oid IdKpServerAuth = Helpers.ConstructOid(IdKp, "1");
        public static readonly Oid IdKpClientAuth = Helpers.ConstructOid(IdKp, "2");
        public static readonly Oid IdKpCodeSigning = Helpers.ConstructOid(IdKp, "3");
        public static readonly Oid IdKpEmailProtection = Helpers.ConstructOid(IdKp, "4");
        public static readonly Oid IdKpIpsecEndSystem = Helpers.ConstructOid(IdKp, "5");
        public static readonly Oid IdKpIpsecTunnel = Helpers.ConstructOid(IdKp, "6");
        public static readonly Oid IdKpIpsecUser = Helpers.ConstructOid(IdKp, "7");
        public static readonly Oid IdKpTimeStamping = Helpers.ConstructOid(IdKp, "8");
        public static readonly Oid IdKpOcspSigning = Helpers.ConstructOid(IdKp, "9");
        public static readonly Oid AnyExtendedKeyUsage = Helpers.ConstructOid(CertificateExtensions.IdCeExtKeyUsage, "0");
        public static readonly Oid IdKpIkeIntermediate = Helpers.ConstructOid("1.3.6.1.5.5.8.2.2");
    }


    /// <summary>Microsoft-specific extended use OIDs</summary>
    /// <remarks>Source: https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage </remarks>
    public static class Microsoft
    {
        public static readonly Oid XcnOidMicrosoft = Helpers.ConstructOid("1.3.6.1.4.1.311");
        public static readonly Oid XcnOidKpCtlUsageSigning = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.1");
        public static readonly Oid XcnOidKpTimeStampSigning = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.2");
        public static readonly Oid XcnOidKpEfs = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.4");
        public static readonly Oid XcnOidEfsRecovery = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.4.1");
        public static readonly Oid XcnOidWhqlCrypto = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.5");
        public static readonly Oid XcnOidNt5Crypto = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.7");
        public static readonly Oid XcnOidOemWhqlCrypto = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.7");
        public static readonly Oid XcnOidEmbeddedNtCrypto = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.8");
        public static readonly Oid XcnOidRootListSigner = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.9");
        public static readonly Oid XcnOidKpQualifiedSubordination = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.10");
        public static readonly Oid XcnOidKpKeyRecovery = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.11");
        public static readonly Oid XcnOidKpDocumentSigning = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.12");
        public static readonly Oid XcnOidKpLifetimeSigning = Helpers.ConstructOid(XcnOidMicrosoft, "10.3.13");
        public static readonly Oid XcnOidDrm = Helpers.ConstructOid(XcnOidMicrosoft, "10.5.1");
        public static readonly Oid XcnOidLicenses = Helpers.ConstructOid(XcnOidMicrosoft, "10.6.1");
        public static readonly Oid XcnOidLicenseServer = Helpers.ConstructOid(XcnOidMicrosoft, "10.6.2");
        public static readonly Oid XcnOidAnyApplicationPolicy = Helpers.ConstructOid(XcnOidMicrosoft, "10.12.1");
        public static readonly Oid XcnOidAutoEnrollCtlUsage = Helpers.ConstructOid(XcnOidMicrosoft, "20.1");
        public static readonly Oid XcnOidEnrollmentAgent = Helpers.ConstructOid(XcnOidMicrosoft, "20.2.1");
        public static readonly Oid XcnOidDsEmailReplication = Helpers.ConstructOid(XcnOidMicrosoft, "21.19");
        public static readonly Oid XcnOidKpSmartcardLogon = Helpers.ConstructOid(XcnOidMicrosoft, "20.2.2");
        public static readonly Oid XcnOidKpCaExchange = Helpers.ConstructOid(XcnOidMicrosoft, "21.5");
        public static readonly Oid XcnOidKpKeyRecoveryAgent = Helpers.ConstructOid(XcnOidMicrosoft, "21.6");
        public static readonly Oid XcnOidPkixKpServerAuth = CertificateUses.IdKpServerAuth;
        public static readonly Oid XcnOidPkixKpClientAuth = CertificateUses.IdKpClientAuth;
        public static readonly Oid XcnOidPkixKpCodeSigning = CertificateUses.IdKpCodeSigning;
        public static readonly Oid XcnOidPkixKpEmailProtection = CertificateUses.IdKpEmailProtection;
        public static readonly Oid XcnOidPkixKpIpsecEndSystem = CertificateUses.IdKpIpsecEndSystem;
        public static readonly Oid XcnOidPkixKpIpsecTunnel = CertificateUses.IdKpIpsecTunnel;
        public static readonly Oid XcnOidPkixKpIpsecUser = CertificateUses.IdKpIpsecUser;
        public static readonly Oid XcnOidPkixKpOcspSigning = CertificateUses.IdKpOcspSigning;
        public static readonly Oid XcnOidPkixKpTimestampSigning = CertificateUses.IdKpTimeStamping;
        public static readonly Oid XcnOidIpsecKpIkeIntermediate = CertificateUses.IdKpIpsecEndSystem;
    }

    /// <summary>Non-standard OIDs</summary>
    /// <remarks>Not part of RFC 5280, and officially deprecated, but 
    /// popular none the less where building certificates for internal use.</remarks>
    public static class NonStandard
    {
        public static readonly Oid NsComment = Helpers.ConstructOid("2.16.840.1.113730.1.13");
    }

    /// <summary>Public key algorithm OIDs from RFC3279</summary>
    public static class KeyAlgorithm
    {
        public static readonly Oid RsaEncryption = Helpers.ConstructOid("1.2.840.113549.1.1.1");
        public static readonly Oid IdEcPublicKey = Helpers.ConstructOid("1.2.840.10045.2.1");
    }

    internal static class Helpers
    {
        /// <summary>
        /// Create a new OID object
        /// </summary>
        /// <param name="oid">OID to create</param>
        /// <returns>OID object</returns>
        /// <remarks>Exists only to make consistent the construction and maintenance 
        /// of OIDs in the section above, so all OIDs are created with the same method.
        /// </remarks>
        internal static Oid ConstructOid(string oid)
        {
            return new Oid(oid);
        }

        /// <summary>
        /// Create a new OID child from a parent OID
        /// </summary>
        /// <param name="parent">Parent OID</param>
        /// <param name="child">Child suffix of OID</param>
        /// <returns>OID object</returns>
        internal static Oid ConstructOid(Oid parent, string child)
        {
            return new Oid($"{parent.Value}.{child}");
        }
    }
}
