namespace Nightwolf.DerEncoder
{
    using System.Text;

    /// <summary>
    /// Class to encode a string to DER bytes
    /// </summary>
    public sealed class DerUtf8String : DerEncoderBase
    {
        /// <summary>Bytes of encoded value</summary>
        private byte[] asnData;

        /// <summary>String to be encoded</summary>
        private readonly string str;

        /// <summary>
        /// Initialize an instance of DerBoolean
        /// </summary>
        /// <param name="val">Value to encode</param>
        public DerUtf8String(string str)
        {
            this.str = str;
            this.UpdateAsnData();
        }

        /// <summary>
        /// Return original string to be encoded
        /// </summary>
        /// <returns>Value encoded</returns>
        public override string ToString()
        {
            return this.str;
        }

        /// <summary>
        /// Return value as ASN.1 DER byte array
        /// </summary>
        /// <returns>DER raw data</returns>
        public override byte[] GetBytes()
        {
            return this.asnData;
        }

        /// <summary>
        /// Create the DER encoding of the string
        /// </summary>
        private void UpdateAsnData()
        {
            if (this.str == null)
            {
                this.asnData = AsnNull;
                return;
            }

            if (this.str.Length == 0)
            {
                this.asnData = BuildPrimitiveAsn1Data(Tag.Utf8String, 0);
                return;
            }

            var charbytes = Encoding.UTF8.GetBytes(this.str);
            this.asnData = BuildPrimitiveAsn1Data(Tag.Utf8String, charbytes);
        }
    }
}
