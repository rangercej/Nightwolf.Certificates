namespace Nightwolf.DerEncoder
{
    /// <summary>
    /// Class to encode a boolean to DER bytes
    /// </summary>
    public sealed class DerBoolean : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of DerBoolean
        /// </summary>
        /// <param name="val">Value to encode</param>
        public DerBoolean(bool val)
        {
            this.Value = val;
            this.EncodedValue = val ? new byte[]{ 0xff } : new byte[]{ 0x0 };
            this.IsConstructed = false;
            this.Tag = (byte)X680Tag.Boolean;
            this.TagClass = X690TagClass.Universal;
        }
    }
}
