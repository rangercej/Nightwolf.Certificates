using System;

namespace Nightwolf.DerEncoder
{
    using System.Text;

    public sealed class DerIa5String : DerEncoderBase
    {
        private byte[] asnData;
        private readonly string str;

        public DerIa5String(string str)
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
                this.asnData = BuildPrimitiveAsn1Data(Tag.Ia5String, 0);
                return;
            }

            var charbytes = Encoding.ASCII.GetBytes(this.str);
            this.asnData = BuildPrimitiveAsn1Data(Tag.Ia5String, charbytes);
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
