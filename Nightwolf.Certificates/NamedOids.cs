using System.Security.Cryptography;

namespace Nightwolf.Certificates
{
    /// <summary>
    /// Named OIDs from RFC 5280
    /// </summary>
    public static class NamedOids
    {
        public static Oid ArcIdPkix = new Oid("1.3.6.1.5.5.7");
        public static Oid ArcIdPe = new Oid("1.3.6.15.5.7.1");
        public static Oid ArcIdCe = new Oid("2.5.29");

        public static Oid CertificatePolicy = new Oid(ArcIdCe.Value + ".32");
        public static Oid CertificatePolicyAny = new Oid(ArcIdCe.Value + ".32.0");

        public static Oid PolicyQualifierId = new Oid(ArcIdPkix.Value + ".2");
        public static Oid PolicyQualifierIdCps = new Oid(PolicyQualifierId.Value + ".1");
        public static Oid PolicyQualifierIdUnotice = new Oid(PolicyQualifierId.Value + ".2");
        
        public static Oid NsComment = new Oid("2.16.840.1.113730.1.13");
    }
}
