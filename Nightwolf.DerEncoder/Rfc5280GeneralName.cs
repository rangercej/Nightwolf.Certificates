namespace Nightwolf.DerEncoder
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Mail;
    using System.Security.Cryptography;

    /// <summary>
    /// Generate an RFC5280 ASN.1 encoded GeneralName 
    /// </summary>
    /// <remarks>
    /// The RFC defines GeneralName as:
    /// 
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
        /// <summary>
        /// Types of general name
        /// </summary>
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

        /// <summary>
        /// Create an Rfc5280GeneralName object
        /// </summary>
        /// <param name="nameType">Type of name to create</param>
        /// <param name="value">Value of general name</param>
        /// <remarks>
        /// IP address must be provided in the form ip.ip.ip.ip/dotted-quad-netmask (e.g., 10.1.1.2/255.255.255.255).
        /// </remarks>
        public Rfc5280GeneralName(GeneralNameType nameType, string value)
        {
            switch (nameType)
            {
                case GeneralNameType.Rfc822Name:
                case GeneralNameType.DnsName:
                case GeneralNameType.UniformResourceIdentifier:
                    CreateTaggedObject(nameType, new X690Ia5String(value));
                    break;
                case GeneralNameType.RegisteredId:
                    CreateTaggedObject(nameType, new X690Oid(new Oid(value)));
                    break;
                case GeneralNameType.IpAddress:
                    var parts = value.Split('/');
                    var ip = IPAddress.Parse(parts[0]);
                    var netmask = IPAddress.Parse(parts[1]);

                    var bytes = new List<byte>();
                    bytes.AddRange(ip.GetAddressBytes());
                    bytes.AddRange(netmask.GetAddressBytes());

                    CreateTaggedObject(nameType, new X690OctetString(bytes));
                    break;
                default:
                    throw new NotSupportedException("Not yet supported.");
            }
        }

        /// <summary>
        /// Create an Rfc5280GeneralName object
        /// </summary>
        /// <param name="ip">IP Address</param>
        /// <param name="netmask">Netmask</param>
        public Rfc5280GeneralName(IPAddress ip, IPAddress netmask)
        {
            var bytes = new List<byte>();
            bytes.AddRange(ip.GetAddressBytes());
            bytes.AddRange(netmask.GetAddressBytes());

            CreateTaggedObject(GeneralNameType.IpAddress, new X690OctetString(bytes));
        }

        /// <summary>
        /// Create an Rfc5280GeneralName object
        /// </summary>
        /// <param name="value">Value of general name</param>
        public Rfc5280GeneralName(MailAddress value)
        {
            CreateTaggedObject(GeneralNameType.Rfc822Name, new X690Ia5String(value.Address));
        }

        /// <summary>
        /// Create an Rfc5280GeneralName object
        /// </summary>
        /// <param name="value">Value of general name</param>
        public Rfc5280GeneralName(Uri value)
        {
            CreateTaggedObject(GeneralNameType.UniformResourceIdentifier, new X690Ia5String(value.AbsoluteUri));
        }

        /// <summary>
        /// Create an Rfc5280GeneralName object
        /// </summary>
        /// <param name="value">Value of general name</param>
        public Rfc5280GeneralName(Oid value)
        {
            CreateTaggedObject(GeneralNameType.RegisteredId, new X690Oid(value));
        }

        /// <summary>
        /// Create the tagged GeneralName object
        /// </summary>
        /// <param name="nameType">Type of name to create</param>
        /// <param name="value">Value of general name</param>
        private void CreateTaggedObject(GeneralNameType nameType, DerEncoderBase value)
        {
            var taggedObject = new X690TaggedObject((byte)nameType, false, value);
            this.TagClass = taggedObject.TagClass;
            this.IsConstructed = taggedObject.IsConstructed;
            this.Tag = taggedObject.Tag;
            this.EncodedValue = taggedObject.EncodedValue;
        }
    }
}
