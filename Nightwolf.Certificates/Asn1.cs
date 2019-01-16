namespace Nightwolf.Certificates
{
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// Implement ToAsn1() extension method of various datatypes.
    /// </summary>
    /// <remarks>
    /// Implements ASN.1 encoding as defined in X.680 and X.690.
    /// </remarks>
    public static class Asn1
    {
        /// <summary>
        /// NULL in ASN.1 format
        /// </summary>
        public static readonly byte[] AsnNull = { (byte)Tag.Null, 0 };

        /// <summary>
        /// ASN.1 tags as defined by X.680, section 8.6
        /// </summary>
        /// <remarks>
        /// Source: https://www.itu.int/rec/T-REC-X.680-201508-I/en
        /// </remarks>
        public enum Tag : byte
        {
            /// <summary>Boolean type</summary>
            Boolean = 1,

            /// <summary>Integer type</summary>
            Integer = 2,

            /// <summary>Null type</summary>
            Null = 5,

            /// <summary>Object identifier type</summary>
            Oid = 6,

            /// <summary>Utf8String type</summary>
            Utf8String = 12,

            /// <summary>Time type</summary>
            Time = 14,

            /// <summary>DATE type</summary>
            Date = 31,

            /// <summary>TIME-OF-DAY type</summary>
            TimeOfDay = 32,

            /// <summary>DATE-TIME type</summary>
            DateTime = 33,

            /// <summary>DURATION type</summary>
            Duration = 34
        }

        /// <summary>
        /// Convert boolean to ASN.1 boolean
        /// </summary>
        /// <param name="val">Value to convert</param>
        /// <returns>ASN.1 byte array</returns>
        internal static byte[] ToAsn1(this bool val)
        {
            return val 
                    ? ConstructAsn1Data(Tag.Boolean, 0xff) 
                    : ConstructAsn1Data(Tag.Boolean, 0x0);
        }

        /// <summary>
        /// Convert int to ASN.1 integer
        /// </summary>
        /// <param name="val">Value to convert</param>
        /// <returns>ASN.1 byte array</returns>
        internal static byte[] ToAsn1(this int val)
        {
            var intAsUint = unchecked((uint)val);

            byte b3 = (byte)((val & 0xff000000) >> 24);
            byte b2 = (byte)((val & 0xff0000) >> 16);
            byte b1 = (byte)((val & 0xff00) >> 8);
            byte b0 = (byte)(val & 0xff);

            if (intAsUint <= 0xff)
            {
                return ConstructAsn1Data(Tag.Integer, b0);
            }

            if (intAsUint <= 0xffff)
            {
                return ConstructAsn1Data(Tag.Integer, b1, b0);
            }

            if (intAsUint <= 0xffffff)
            {
                return ConstructAsn1Data(Tag.Integer, b2, b1, b0);
            }

            return ConstructAsn1Data(Tag.Integer, b3, b2, b1, b0);
        }

        /// <summary>
        /// Convert string to ASN.1 Utf8String
        /// </summary>
        /// <param name="str">String to convert</param>
        /// <returns>ASN.1 byte array</returns>
        internal static byte[] ToAsn1(this string str)
        {
            if (str == null)
            {
                return AsnNull;
            }

            if (str.Length == 0)
            {
                return ConstructAsn1Data(Tag.Utf8String, 0);
            }

            var charbytes = Encoding.UTF8.GetBytes(str);
            return ConstructAsn1Data(Tag.Utf8String, charbytes);
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        private static byte[] ConstructAsn1Data(Tag tag, params byte[] data)
        {
            var bytes = new List<byte>(16);
            var len = data != null ? (uint)data.Length : 0;
            var lenbytes = ConstructLength(len);

            bytes.Add((byte)tag);
            bytes.AddRange(lenbytes);

            if (data != null && len > 0)
            {
                bytes.AddRange(data);
            }

            return bytes.ToArray();
        }

        /// <summary>
        /// Construct an ASN.1 length specifier
        /// </summary>
        /// <param name="len">Length to convert to ASN.1 bytes</param>
        /// <returns>ASN.1 length</returns>
        /// <remarks>X.690, section 8.1.3</remarks>
        private static byte[] ConstructLength(uint len)
        {
            if (len <= 0x7f)
            {
                return new[] { (byte)len };
            }

            byte b3 = (byte)((len & 0xff000000) >> 24);
            byte b2 = (byte)((len & 0xff0000) >> 16);
            byte b1 = (byte)((len & 0xff00) >> 8);
            byte b0 = (byte)(len & 0xff);

            if (len <= 0xff)
            {
                return new[] { (byte)0x81, b0 };
            }

            if (len <= 0xffff)
            {
                return new[] { (byte)0x82, b1, b0 };
            }

            if (len <= 0xffffff)
            {
                return new[] { (byte)0x83, b2, b1, b0 };
            }

            return new[] { (byte)0x84, b3, b2, b1, b0 };
        }
    }
}
