namespace Nightwolf.DerEncoder
{
    using System.Text;

    /// <summary>
    /// Class to encode a string to DER bytes
    /// </summary>
    public sealed class DerUtf8String : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of DerBoolean
        /// </summary>
        /// <param name="val">Value to encode</param>
        public DerUtf8String(string str)
        {
            this.Value = str;
            this.UpdateAsnData(str);
            this.IsConstructed = false;
            this.Tag = (byte)X680Tag.Utf8String;
            this.TagClass = X690TagClass.Universal;
        }

        /// <summary>
        /// Create the DER encoding of the string
        /// </summary>
        private void UpdateAsnData(string str)
        {
            if (str == null)
            {
                this.EncodedValue = AsnNull;
                return;
            }

            if (str.Length == 0)
            {
                return;
            }

            this.EncodedValue = Encoding.UTF8.GetBytes(str);
        }
    }
}
