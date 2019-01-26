namespace Nightwolf.DerEncoder
{
    using System.Collections.Generic;

    public abstract class DerEncoderBase
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

            /// <summary>Sequence</summary>
            Sequence = 16,

            /// <summary>IA5 string type</summary>
            Ia5String = 22,
            
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
        /// Convert data to ASN.1 byte array
        /// </summary>
        /// <returns>ASN.1 raw data</returns>
        public abstract byte[] GetBytes();

        /// <summary>
        /// Return value in encoded data as string
        /// </summary>
        /// <returns>Value encoded</returns>
        public abstract override string ToString();

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildPrimitiveAsn1Data(Tag tag, params byte[] data)
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
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildPrimitiveAsn1Data(Tag tag, List<byte> data)
        {
            var bytes = new List<byte>(16);
            var len = data != null ? (uint)data.Count : 0;
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
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildConstructedAsn1Data(Tag tag, params byte[] data)
        {
            var bytes = new List<byte>(16);
            var len = data != null ? (uint)data.Length : 0;
            var lenbytes = ConstructLength(len);

            var ident = (byte) ((byte) tag | (1 << 5));
            bytes.Add(ident);
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
        protected static byte[] ConstructLength(uint len)
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
