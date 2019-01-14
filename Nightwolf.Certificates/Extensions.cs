using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nightwolf.Certificates
{
    internal static class Extensions
    {
        internal static byte[] ToAsn1String(this string str)
        {
            if (str.Length > 255)
            {
                throw new ArgumentException("String too long for ASN.1 conversion");
            }

            if (str == null)
            {
                throw new ArgumentNullException(nameof(str), "Cannot convert null string to ASN.1");
            }

            if (str.Length == 0)
            {
                return new byte[] { 12, 0 };
            }

            var charbytes = Encoding.UTF8.GetBytes(str);
            byte[] asn1 = new byte[2 + charbytes.Length];

            asn1[0] = 12; // ASN.1 tag for UTF8
            asn1[1] = (byte)charbytes.Length;
            Buffer.BlockCopy(charbytes, 0, asn1, 2, charbytes.Length);

            return asn1;
        }
    }
}
