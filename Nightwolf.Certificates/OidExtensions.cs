namespace Nightwolf.Certificates
{
    using System.Security.Cryptography;

    public static class OidExtensions
    {
        /// <summary>
        /// Does this OID match the value of the target OID
        /// </summary>
        /// <param name="source">Source OID</param>
        /// <param name="target">Target OID</param>
        /// <returns>True when OID values match</returns>
        public static bool Matches(this Oid source, Oid target)
        {
            return source.Value == target.Value;
        }

        /// <summary>
        /// Does this OID match the value of the target OID
        /// </summary>
        /// <param name="source">Source OID</param>
        /// <param name="target">Target OID</param>
        /// <returns>True when OID values match</returns>
        public static bool Matches(this Oid source, string target)
        {
            return source.Value == target;
        }
    }
}
