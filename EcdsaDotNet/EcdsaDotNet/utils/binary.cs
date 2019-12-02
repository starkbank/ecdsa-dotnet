using System.Globalization;
using System.Numerics;
using System.Text;
using System;


namespace EllipticCurve.Utils {

    public static class BinaryAscii {

        public static string hexFromBinary(string byteAsciiString) {
            byte[] byteArray = Encoding.ASCII.GetBytes(byteAsciiString);
            StringBuilder hex = new StringBuilder(byteArray.Length * 2);
            foreach (byte b in byteArray)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static string binaryFromHex(string hexString) {
            int numberChars = hexString.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return Encoding.ASCII.GetString(bytes);
        }

        public static BigInteger numberFromHex(string hex) {
            return BigInteger.Parse(hex, NumberStyles.AllowHexSpecifier);
        }

        public static string hexFromNumber(BigInteger number, int length) {
            string formatString = "%0" + (2 * length).ToString() + "X";
            return binaryFromHex(number.ToString(formatString));
        }

    }

}
