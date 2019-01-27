namespace Nightwolf.DerEncoder
{
    /// <summary>
    /// Class to encode a boolean to DER bytes
    /// </summary>
    public sealed class DerBoolean : DerEncoderBase
    {
        /// <summary>Value to be encoded</summary>
        private readonly bool val;

        /// <summary>Bytes of encoded value</summary>
        private readonly byte[] asnBytes;

        /// <summary>
        /// Initialize an instance of DerBoolean
        /// </summary>
        /// <param name="val">Value to encode</param>
        public DerBoolean(bool val)
        {
            this.val = val;
            this.asnBytes = this.val
                ? BuildPrimitiveAsn1Data(Tag.Boolean, 0xff)
                : BuildPrimitiveAsn1Data(Tag.Boolean, 0x0);
        }

        /// <summary>
        /// Return value as ASN.1 DER byte array
        /// </summary>
        /// <returns>DER raw data</returns>
        public override byte[] GetBytes()
        {
            return this.asnBytes;
        }

        /// <summary>
        /// Return value encoded in DER
        /// </summary>
        /// <returns>Value encoded</returns>
        public override string ToString()
        {
            return this.val.ToString();
        }
    }
}
