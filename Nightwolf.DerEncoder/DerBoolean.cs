namespace Nightwolf.DerEncoder
{
    public sealed class DerBoolean : DerEncoderBase
    {
        private readonly bool val;
        private readonly byte[] asnBytes;

        public DerBoolean(bool val)
        {
            this.val = val;
            this.asnBytes = this.val
                ? BuildPrimitiveAsn1Data(Tag.Boolean, 0xff)
                : BuildPrimitiveAsn1Data(Tag.Boolean, 0x0);
        }

        public override byte[] GetBytes()
        {
            return this.asnBytes;
        }

        public override string ToString()
        {
            return this.val.ToString();
        }
    }
}
