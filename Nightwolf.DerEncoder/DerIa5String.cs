using System.Collections.Generic;

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
        /// <summary>
        /// Initialize an instance of DerIa5String
        /// </summary>
        /// <param name="str">Value to encode</param>
        public DerIa5String(string str)
        {
            this.Value = str;
            this.UpdateAsnData(str);
            this.TagClass = X690TagClass.Universal;
            this.Tag = (byte)X680Tag.Ia5String;
            this.IsConstructed = false;
        }

        /// <summary>
        /// Create the DER data bytes
        /// </summary>
        private void UpdateAsnData(string val)
        {
            if (this.Value == null)
            {
                this.EncodedValue = AsnNull;
                return;
            }

            if (val.Length == 0)
            {
                return;
            }

            this.EncodedValue = Encoding.ASCII.GetBytes(val);
        }
    }
}
