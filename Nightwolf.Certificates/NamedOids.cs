namespace Nightwolf.Certificates
{
    using System.Security.Cryptography;

    /// <summary>
    /// Named OIDs from RFC 5280
    /// </summary>
    public static class NamedOids
    {
        public static Oid IdPkix = new Oid("1.3.6.1.5.5.7");
        public static Oid IdPe = new Oid("1.3.6.1.5.5.7.1");
        public static Oid IdCe = new Oid("2.5.29");

        public static Oid IdPeAuthorityInfoAccess = new Oid(IdPe.Value + ".1");

        public static Oid IdCeCrlDistributionPoints = new Oid(IdCe.Value + ".31");

        public static Oid IdCeCertificatePolicies = new Oid(IdCe.Value + ".32");
        public static Oid AnyPolicy = new Oid(IdCe.Value + ".32.0");

        public static Oid IdQt = new Oid(IdPkix.Value + ".2");
        public static Oid IdQtCps = new Oid(IdQt.Value + ".1");
        public static Oid IdQtUnotice = new Oid(IdQt.Value + ".2");
        
        public static Oid IdAd = new Oid(IdPkix.Value + ".48");
        public static Oid IdAdOcsp = new Oid(IdAd.Value + ".1");
        public static Oid IdAdCaIssuers = new Oid(IdAd.Value + ".2");

        public static Oid NsComment = new Oid("2.16.840.1.113730.1.13");
    }
}
