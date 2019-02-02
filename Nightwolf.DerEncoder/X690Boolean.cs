namespace Nightwolf.DerEncoder
{
    /// <summary>
    /// Class to encode a boolean to DER bytes
    /// </summary>
    public sealed class X690Boolean : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of X690Boolean
        /// </summary>
        /// <param name="val">Value to encode</param>
        public X690Boolean(bool val)
        {
            this.Value = val;
            this.EncodedValue = val ? new byte[]{ 0xff } : new byte[]{ 0x0 };
            this.IsConstructed = false;
            this.Tag = (byte)X680Tag.Boolean;
            this.TagClass = X690TagClass.Universal;
        }
    }
}
