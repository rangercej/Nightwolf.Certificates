namespace Nightwolf.DerEncoder
{
    using System.Text;

    /// <summary>
    /// Class to encode a string to IA5 DER bytes
    /// </summary>
    /// <remarks>
    /// IA5 - International Alphabet 5 - is closely related to ASCII, and in
    /// most situations the conversion can be considered as just a change in
    /// name.
    /// </remarks>
    public sealed class DerIa5String : DerEncoderBase
    {
        /// <summary>Bytes of encoded value</summary>
        private byte[] asnData;

        /// <summary>Value to be encoded</summary>
        private readonly string str;

        /// <summary>
        /// Initialize an instance of DerIa5String
        /// </summary>
        /// <param name="str">Value to encode</param>
        public DerIa5String(string str)
        {
            this.str = str;
            this.UpdateAsnData();
        }

        /// <summary>
        /// Return value encoded as DER
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
        /// Create the DER data bytes
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
                this.asnData = BuildPrimitiveAsn1Data(Tag.Ia5String, 0);
                return;
            }

            var charbytes = Encoding.ASCII.GetBytes(this.str);
            this.asnData = BuildPrimitiveAsn1Data(Tag.Ia5String, charbytes);
        }
    }
}
