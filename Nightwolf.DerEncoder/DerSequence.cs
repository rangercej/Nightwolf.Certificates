namespace Nightwolf.DerEncoder
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Class to create a DER sequence
    /// </summary>
    public sealed class DerSequence : DerEncoderBase
    {
        /// <summary>
        /// Items in the sequence
        /// </summary>
        private readonly List<DerEncoderBase> sequenceItems = new List<DerEncoderBase>();

        /// <summary>
        /// Initialize the DerSequence class
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public DerSequence(IEnumerable<DerEncoderBase> items)
        {
            this.sequenceItems.AddRange(items);
        }

        /// <summary>
        /// Initialize the DerSequence class
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public DerSequence(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
        }

        /// <summary>
        /// Initialize an empty DerSequence
        /// </summary>
        public DerSequence()
        {
        }

        /// <summary>
        /// Add items to the end of the sequence
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public void Add(List<DerEncoderBase> items)
        {
            this.sequenceItems.AddRange(items);
        }

        /// <summary>
        /// Add items to the end of the sequence
        /// </summary>
        /// <param name="items">Items to add to the sequence</param>
        public void Add(params DerEncoderBase[] items)
        {
            this.sequenceItems.AddRange(items);
        }

        /// <summary>
        /// Return sequence as ASN.1 DER byte array
        /// </summary>
        /// <returns>DER raw data</returns>
        public override byte[] GetBytes()
        {
            var data = new List<byte>(100);
            foreach (var i in this.sequenceItems)
            {
                data.AddRange(i.GetBytes());
            }

            var sequence = BuildConstructedAsn1Data(Tag.Sequence, data);
            return sequence;
        }

        /// <summary>
        /// Return sequence as string showing encoded vlaues
        /// </summary>
        /// <returns>String data</returns>
        /// <remarks>Not currently implemented.</remarks>
        public override string ToString()
        {
            throw new NotImplementedException();
        }
    }
}
