namespace Nightwolf.DerEncoder
{
    using System.Collections.Generic;

    /// <summary>
    /// Class to create a DER sequence
    /// </summary>
    public sealed class X690Sequence : DerEncoderBase
    {
        /// <summary>
        /// Items in the sequence
        /// </summary>
        private readonly List<DerEncoderBase> sequenceItems = new List<DerEncoderBase>();

        /// <summary>
        /// Initialize the X690Sequence class
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public X690Sequence(IEnumerable<DerEncoderBase> items)
        {
            this.sequenceItems.AddRange(items);
            this.IsConstructed = true;
            this.Tag = (byte)X680Tag.Sequence;
            this.TagClass = X690TagClass.Universal;
            this.UpdateSequenceBytes();
        }

        /// <summary>
        /// Initialize the X690Sequence class
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public X690Sequence(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
            this.IsConstructed = true;
            this.Tag = (byte)X680Tag.Sequence;
            this.TagClass = X690TagClass.Universal;
            this.UpdateSequenceBytes();
        }

        /// <summary>
        /// Initialize an empty X690Sequence
        /// </summary>
        public X690Sequence()
        {
            this.IsConstructed = true;
            this.Tag = (byte)X680Tag.Sequence;
            this.TagClass = X690TagClass.Universal;
            this.UpdateSequenceBytes();
        }

        /// <summary>
        /// Add items to the end of the sequence
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public void Add(List<DerEncoderBase> items)
        {
            this.sequenceItems.AddRange(items);
            this.UpdateSequenceBytes();
        }

        /// <summary>
        /// Add items to the end of the sequence
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public void Add(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
            this.UpdateSequenceBytes();
        }

        /// <summary>
        /// Return sequence as ASN.1 DER byte array
        /// </summary>
        /// <returns>DER raw data</returns>
        public void UpdateSequenceBytes()
        {
            var data = new List<byte>(100);
            foreach (var i in this.sequenceItems)
            {
                data.AddRange(i.GetBytes());
            }

            this.EncodedValue = data.ToArray();
        }

        /// <summary>
        /// Return sequence as string showing encoded vlaues
        /// </summary>
        /// <returns>String data</returns>
        public new string ToString()
        {
            return string.Format("Ident = {0}, Count = {1}, Value = [Sequence]", 
                this.Identifier,
                this.sequenceItems.Count);
        }
    }
}
