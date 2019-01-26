namespace Nightwolf.DerEncoder
{
    using System;
    using System.Collections.Generic;

    public sealed class DerSequence : DerEncoderBase
    {
        private readonly List<DerEncoderBase> sequenceItems = new List<DerEncoderBase>();

        public DerSequence(IEnumerable<DerEncoderBase> items)
        {
            this.sequenceItems.AddRange(items);
        }

        public DerSequence(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
        }

        public void Add(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
        }

        public override byte[] GetBytes()
        {
            var data = new List<byte>(100);
            foreach (var i in this.sequenceItems)
            {
                data.AddRange(i.GetBytes());
            }

            var sequence = BuildConstructedAsn1Data(Tag.Sequence, data.ToArray());
            return sequence;
        }

        public override string ToString()
        {
            throw new NotImplementedException();
        }
    }
}
