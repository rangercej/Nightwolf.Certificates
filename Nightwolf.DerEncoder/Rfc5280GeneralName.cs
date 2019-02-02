using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Nightwolf.DerEncoder
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    ///    GeneralName ::= CHOICE {
    ///        otherName                [0] OtherName,
    ///        rfc822Name               [1] IA5String,
    ///        dNSName                  [2] IA5String,
    ///        x400Address              [3] ORAddress,
    ///        directoryName            [4] Name,
    ///        ediPartyName             [5] EDIPartyName,
    ///        uniformResourceIdentifier[6] IA5String,
    ///        iPAddress                [7] OCTET STRING,
    ///        registeredID             [8] OBJECT IDENTIFIER 
    ///    }
    /// </remarks>
    public sealed class Rfc5280GeneralName : DerEncoderBase
    {
        public enum GeneralNameType : byte
        {
            OtherName = 0,
            Rfc822Name,
            DnsName,
            X400Address,
            DirectoryName,
            EdiPartyName,
            UniformResourceIdentifier,
            IpAddress,
            RegisteredId
        }

        public Rfc5280GeneralName(string emailAddress)
        {
            var taggedObject = new X690TaggedObject((byte)GeneralNameType.Rfc822Name, false, new X690Ia5String(emailAddress));
            this.TagClass = taggedObject.TagClass;
            this.IsConstructed = taggedObject.IsConstructed;
            this.Tag = taggedObject.Tag;
            this.EncodedValue = taggedObject.EncodedValue;
        }

        public Rfc5280GeneralName(Uri item)
        {
            var taggedObject = new X690TaggedObject((byte)GeneralNameType.UniformResourceIdentifier, false, new X690Ia5String(item.AbsoluteUri));
            this.TagClass = taggedObject.TagClass;
            this.IsConstructed = taggedObject.IsConstructed;
            this.Tag = taggedObject.Tag;
            this.EncodedValue = taggedObject.EncodedValue;
        }

        public Rfc5280GeneralName(Oid item)
        {
            var taggedObject = new X690TaggedObject((byte)GeneralNameType.RegisteredId, false, new X690Oid(item));
            this.TagClass = taggedObject.TagClass;
            this.IsConstructed = taggedObject.IsConstructed;
            this.Tag = taggedObject.Tag;
            this.EncodedValue = taggedObject.EncodedValue;
        }
    }
}
