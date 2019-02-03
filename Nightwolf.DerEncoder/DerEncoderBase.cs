using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace Nightwolf.DerEncoder
{
    using System.Collections.Generic;

    public abstract class DerEncoderBase
    {
        /// <summary>
        /// NULL in ASN.1 format
        /// </summary>
        public static readonly byte[] AsnNull = { (byte)X680Tag.Null, 0 };

        /// <summary>
        /// ASN.1 tags as defined by X.680, section 8.6
        /// </summary>
        /// <remarks>
        /// Source: https://www.itu.int/rec/T-REC-X.680-201508-I/en
        /// </remarks>
        public enum X680Tag : byte
        {
            /// <summary>Boolean type</summary>
            Boolean = 1,

            /// <summary>Integer type</summary>
            Integer = 2,

            /// <summary>Octetstring type</summary>
            OctetString = 4,

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
        /// Class of tag, as defined by X.690, sec 8.1.2.
        /// </summary>
        public enum X690TagClass : byte
        {
            /// <summary>Tag is universal</summary>
            Universal = 0,

            /// <summary>Tag is application specific</summary>
            Application = 0b0100_0000,

            /// <summary>Tag is context specific</summary>
            ContextSpecific = 0b1000_0000,

            /// <summary>Tag is privately defined</summary>
            Private = 0b1100_0000
        }

        /// <summary>
        /// Class of the encoded entity
        /// </summary>
        public X690TagClass TagClass { get; protected set; }

        /// <summary>
        /// Flag indicating if the encoded value is constructed or primitive
        /// </summary>
        public bool IsConstructed { get; protected set; }

        /// <summary>
        /// Value that has been encoded
        /// </summary>
        public object Value { get; protected set; }
        
        /// <summary>
        /// Tag identifier of the encoded item
        /// </summary>
        public byte Tag { get; protected set; }

        /// <summary>
        /// Contains the encoded value as ASN.1 bytes
        /// </summary>
        public byte[] EncodedValue { get; protected set; }

        /// <summary>
        /// Identifier byte as defined by X.690, 8.1.2
        /// </summary>
        protected byte Identifier
        {
            get
            {
                var constructedVal = (byte)(this.IsConstructed ? 0b0010_0000 : 0);
                var classVal = (byte) this.TagClass;
                var tagVal = (byte) this.Tag;

                return (byte)(classVal | constructedVal | tagVal);
            }
        }

        /// <summary>
        /// Convert data to ASN.1 byte array
        /// </summary>
        /// <returns>ASN.1 raw data</returns>
        public byte[] GetBytes()
        {
            var bytes = new List<byte> {this.Identifier};
            bytes.AddRange(ConstructLength((uint)this.EncodedValue.Length));
            bytes.AddRange(this.EncodedValue);

            return bytes.ToArray();
        }

        /// <summary>
        /// Return value in encoded data as string
        /// </summary>
        /// <returns>Value encoded</returns>
        public override string ToString()
        {
            return string.Format("Ident = {0:x}, Len = {1}, Val = {2}", 
                this.Identifier, 
                this.EncodedValue.Length,
                this.Value);
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="x680Tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildPrimitiveAsn1Data(X680Tag x680Tag, params byte[] data)
        {
            return BuildInternalDerData((byte)x680Tag, data);
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="x680Tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildPrimitiveAsn1Data(X680Tag x680Tag, IEnumerable<byte> data)
        {
            return BuildInternalDerData((byte)x680Tag, data.ToList());
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildPrimitiveAsn1Data(byte tag, IEnumerable<byte> data)
        {
            return BuildInternalDerData(tag, data.ToList());
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="x680Tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildConstructedAsn1Data(X680Tag x680Tag, IEnumerable<byte> data)
        {
            // Mark tag with constructed flag
            var ident = (byte)((byte)x680Tag | 0b0010_0000);
            return BuildInternalDerData(ident, data.ToList());
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="tag">ASN.1 tag</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        protected static byte[] BuildConstructedAsn1Data(byte tag, IEnumerable<byte> data)
        {
            // Mark tag with constructed flag
            var ident = (byte)(tag | 0b0010_0000);
            return BuildInternalDerData(ident, data.ToList());
        }

        /// <summary>
        /// Construct ASN.1 data
        /// </summary>
        /// <param name="identifier">ASN.1 tag and construction type</param>
        /// <param name="data">Data bytes</param>
        /// <returns>ASN.1 byte array</returns>
        private static byte[] BuildInternalDerData(byte identifier, IList<byte> data)
        {
            var bytes = new List<byte>(16);
            var len = data != null ? (uint)data.Count : 0;
            var lenbytes = ConstructLength(len);

            bytes.Add(identifier);
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
