namespace Nightwolf.DerEncoder
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Class to encode an OID to DER bytes
    /// </summary>
    public sealed class DerOid : DerEncoderBase
    {
        /// <summary>
        /// Initialize an instance of DerOid
        /// </summary>
        /// <param name="oid">Value to encode</param>
        public DerOid(Oid oid)
        {
            this.Value = oid;
            this.EncodeOid(oid);
            this.IsConstructed = false;
            this.Tag = (byte)X680Tag.Oid;
            this.TagClass = X690TagClass.Universal;
        }

        /// <summary>
        /// Encode an OID into an appropriate bitstream
        /// </summary>
        /// <returns>Packed bytes</returns>
        /// <remarks>
        /// As per X690, sec 8.19 we split the OID into its constituent
        /// components, then pack each component into a 7-bit word. The
        /// first two components are treated as one, and merged by the
        /// formula: val = (x * 40) + y.
        /// </remarks>
        private void EncodeOid(Oid oid)
        {
            var derbytes = new List<byte>();

            var components = oid.Value.Split('.').Select(ulong.Parse);
            using (var iterator = components.GetEnumerator())
            {
                iterator.MoveNext();
                var firstSubId = iterator.Current * 40;
                iterator.MoveNext();
                firstSubId += iterator.Current;

                var bytes = PackSubId(firstSubId);
                derbytes.AddRange(bytes);
                while (iterator.MoveNext())
                {
                    bytes = PackSubId(iterator.Current);
                    derbytes.AddRange(bytes);
                }
            }

            this.EncodedValue = derbytes.ToArray();
        }

        /// <summary>
        /// Pack a 64-bit word into 7-bit octets, as per X.690, sec 8.19
        /// </summary>
        /// <param name="subid">64-bit subidentifier to encode</param>
        /// <returns>Packed bytes</returns>
        /// <remarks>
        /// The MSB of each octet acts as a flag to indicate if it's the
        /// last octet that makes the stream up. If it's set, then there's
        /// more bytes to follow; the last octet has the MSB set to 0.
        /// 
        /// Additionally X.690 wants the minimum number of bytes, so we
        /// track the earliest non-zero octet so we can skip all the 
        /// zero-bytes at the start of the word.
        /// </remarks>
        private IEnumerable<byte> PackSubId(ulong subid)
        {
            // 8-byte long packs into 9.1428 7-bit words
            var octets = new byte[10];
            
            var nonzero = 9;
            for (var i = 9; i >= 0; i--)
            {
                octets[i] = (byte)((subid & 0x7f) | 0x80);
                if (octets[i] != 0x80)
                {
                    nonzero = i;
                }

                subid >>= 7;
            }

            octets[9] &= 0x7f;

            var b = octets.Skip(nonzero);
            return b;
        }
    }
}
