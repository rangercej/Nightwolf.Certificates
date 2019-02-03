namespace Nightwolf.DerEncoder
{
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Class to encode a byte array
    /// </summary>
    public sealed class X690OctetString : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of X690OctetString
        /// </summary>
        /// <param name="value">Bytes to encode</param>
        public X690OctetString(IEnumerable<byte> value)
        {
            this.Value = value;
            this.EncodedValue = value.ToArray();
            this.TagClass = X690TagClass.Universal;
            this.Tag = (byte)X680Tag.OctetString;
            this.IsConstructed = false;
        }

        /// <summary>
        /// Initialize an instance of X690OctetString
        /// </summary>
        /// <param name="value">Bytes to encode</param>
        public X690OctetString(byte[] value)
        {
            this.Value = value;
            this.EncodedValue = value;
            this.TagClass = X690TagClass.Universal;
            this.Tag = (byte)X680Tag.OctetString;
            this.IsConstructed = false;
        }
    }
}
