using System.Globalization;
using System.Numerics;
using System.Text;
using System;


namespace EllipticCurve.Utils {

    public static class BinaryAscii {

        public static string hexFromBinary(byte[] bytes) {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        public static byte[] binaryFromHex(string hexString) {
            int numberChars = hexString.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars - 1; i += 2) {
                bytes[i / 2] = Convert.ToByte(String.substring(hexString, i, 2), 16);
            }
            return bytes;
        }

        public static BigInteger numberFromHex(string hex) {
            if (((hex.Length % 2) == 1) | hex[0] != '0') {
                hex = "0" + hex; // if the hex string doesnt start with 0, the parse will assume its negative
            }
            return BigInteger.Parse(hex, NumberStyles.HexNumber);
        }

        public static string hexFromNumber(BigInteger number, int length) {
            string formatString = "X" + (2 * length).ToString();
            return number.ToString(formatString);
        }

    }

}