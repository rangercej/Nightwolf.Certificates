namespace Nightwolf.DerEncoder
{
    using System.Text;

    public sealed class DerUtf8String : DerEncoderBase
    {
        private byte[] asnData;
        private readonly string str;

        public DerUtf8String()
        {
            this.str = null;
            this.UpdateAsnData();
        }

        public DerUtf8String(string str)
        {
            this.str = str;
            this.UpdateAsnData();
        }

        private void UpdateAsnData()
        {
            if (this.str == null)
            {
                this.asnData = AsnNull;
                return;
            }

            if (this.str.Length == 0)
            {
                this.asnData = BuildPrimitiveAsn1Data(Tag.Utf8String, 0);
                return;
            }

            var charbytes = Encoding.UTF8.GetBytes(this.str);
            this.asnData = BuildPrimitiveAsn1Data(Tag.Utf8String, charbytes);
        }

        public override string ToString()
        {
            return this.str;
        }

        public override byte[] GetBytes()
        {
            return this.asnData;
        }
    }
}
