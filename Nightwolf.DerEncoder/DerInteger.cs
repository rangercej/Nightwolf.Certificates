namespace Nightwolf.DerEncoder
{
    public sealed class DerInteger : DerEncoderBase
    {
        private readonly int val;
        private byte[] asnBytes;

        public DerInteger(int val)
        {
            this.val = val;
            this.UpdateAsnData(val);
        }

        public override byte[] GetBytes()
        {
            return this.asnBytes;
        }

        public override string ToString()
        {
            return this.val.ToString();
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
                this.asnBytes = BuildPrimitiveAsn1Data(Tag.Integer, b0);
                return;
            }

            if (intAsUint <= 0xffff)
            {
                this.asnBytes = BuildPrimitiveAsn1Data(Tag.Integer, b1, b0);
                return;
            }

            if (intAsUint <= 0xffffff)
            {
                this.asnBytes = BuildPrimitiveAsn1Data(Tag.Integer, b2, b1, b0);
                return;
            }

            this.asnBytes = BuildPrimitiveAsn1Data(Tag.Integer, b3, b2, b1, b0);
        }
    }
}
