namespace Nightwolf.DerEncoder
{
    using System;

    /// <summary>
    /// DER tagged object
    /// </summary>
    /// <remarks>
    /// X.680, sec 31.2; X.690, 8.14
    /// </remarks>
    public sealed class DerTaggedObject : DerEncoderBase
    {
        public DerTaggedObject(byte asnClass, bool explicitFlag, DerEncoderBase item)
        {
            if (asnClass > 30)
            {
                throw new NotSupportedException("Class with value greater than 30 not currently supported.");
            }

            this.Tag = asnClass;
            this.TagClass = X690TagClass.ContextSpecific;
            this.IsConstructed = explicitFlag || item.IsConstructed;
            this.EncodedValue = explicitFlag ? item.GetBytes() : item.EncodedValue;
        }
    }
}
