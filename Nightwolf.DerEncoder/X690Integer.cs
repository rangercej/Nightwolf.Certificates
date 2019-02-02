namespace Nightwolf.DerEncoder
{
    /// <summary>
    /// Class to encode a integer to DER bytes
    /// </summary>
    public sealed class X690Integer : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of X690Integer
        /// </summary>
        /// <param name="val">Value to encode</param>
        public X690Integer(int val)
        {
            this.Value = val;
            this.UpdateAsnData(val);
            this.IsConstructed = false;
            this.Tag = (byte) X680Tag.Integer;
            this.TagClass = X690TagClass.Universal;
        }

        private void UpdateAsnData(int val)
        {
            var intAsUint = unchecked((uint) val);

            byte b3 = (byte) ((val & 0xff000000) >> 24);
            byte b2 = (byte) ((val & 0xff0000) >> 16);
            byte b1 = (byte) ((val & 0xff00) >> 8);
            byte b0 = (byte) (val & 0xff);

            if (intAsUint <= 0xff)
            {
                this.EncodedValue = new[] { b0 };
                return;
            }

            if (intAsUint <= 0xffff)
            {
                this.EncodedValue = new[] { b1, b0 };
                return;
            }

            if (intAsUint <= 0xffffff)
            {
                this.EncodedValue = new[] { b2, b1, b0 };
                return;
            }

            this.EncodedValue = new[] { b3, b2, b1, b0 };
        }
    }
}
