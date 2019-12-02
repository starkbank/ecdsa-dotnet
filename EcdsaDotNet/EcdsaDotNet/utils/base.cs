using System.Text;
using System;

namespace EllipticCurve.Utils {

    public static class Base64 {

        public static string decode(string base64String) {
            byte[] decodedByteArray = Convert.FromBase64String(base64String);
            return Encoding.ASCII.GetString(decodedByteArray);
        }

        public static string encode(string base64AsciiBytes) {
            byte[] base64Bytes = Encoding.ASCII.GetBytes(base64AsciiBytes);
            return Encoding.UTF8.GetString(base64Bytes, 0, base64Bytes.Length);
        }

    }

}
