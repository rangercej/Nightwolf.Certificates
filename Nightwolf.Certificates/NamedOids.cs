namespace Nightwolf.Certificates
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
    public static class NamedOids
    {
        public static Oid IdPkix = ConstructOid("1.3.6.1.5.5.7");
        public static Oid IdPe = ConstructOid("1.3.6.1.5.5.7.1");
        public static Oid IdCe = ConstructOid("2.5.29");

        public static Oid IdPeAuthorityInfoAccess = ConstructOid(IdPe, "1");

        public static Oid IdCeCrlDistributionPoints = ConstructOid(IdCe, "31");

        public static Oid IdCeCertificatePolicies = ConstructOid(IdCe, "32");
        public static Oid AnyPolicy = ConstructOid(IdCe, "32.0");

        public static Oid IdQt = ConstructOid(IdPkix, "2");
        public static Oid IdQtCps = ConstructOid(IdQt, "1");
        public static Oid IdQtUnotice = ConstructOid(IdQt, "2");
        
        public static Oid IdAd = ConstructOid(IdPkix, "48");
        public static Oid IdAdOcsp = ConstructOid(IdAd, "1");
        public static Oid IdAdCaIssuers = ConstructOid(IdAd, "2");

        /// <remarks>Not part of RFC 5280, and officially deprecated, but 
        /// popular none the less where building certificates for internal use.</remarks>
        public static Oid NsComment = ConstructOid("2.16.840.1.113730.1.13");

        /// <summary>
        /// Create a new OID object
        /// </summary>
        /// <param name="oid">OID to create</param>
        /// <returns>OID object</returns>
        /// <remarks>Exists only to make consistent the construction and maintenance 
        /// of OIDs in the section above, so all OIDs are created with the same method.
        /// </remarks>
        private static Oid ConstructOid(string oid)
        {
            return new Oid(oid);
        }

        /// <summary>
        /// Create a new OID child from a parent OID
        /// </summary>
        /// <param name="parent">Parent OID</param>
        /// <param name="child">Child suffix of OID</param>
        /// <returns>OID object</returns>
        private static Oid ConstructOid(Oid parent, string child)
        {
            return new Oid($"{parent.Value}.{child}");
        }
    }
}
