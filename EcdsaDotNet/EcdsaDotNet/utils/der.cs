using System.Collections.Generic;
using System.Numerics;
using System;

namespace EllipticCurve.Utils {

    public static class Der
    {
        private static string hexAt = "\x00";
        private static string hexB = "\x02";
        private static string hexC = "\x03";
        private static string hexD = "\x04";
        private static string hexF = "\x06";
        private static string hex0 = "\x30";

        private static int hex31 = 0x1f;
        private static int hex127 = 0x7f;
        private static int hex129 = 0xa0;
        private static int hex160 = 0x80;
        private static int hex224 = 0xe0;

        private static string bytesHex0 = BinaryAscii.binaryFromHex(hex0);
        private static string bytesHexB = BinaryAscii.binaryFromHex(hexB);
        private static string bytesHexC = BinaryAscii.binaryFromHex(hexC);
        private static string bytesHexD = BinaryAscii.binaryFromHex(hexD);
        private static string bytesHexF = BinaryAscii.binaryFromHex(hexF);

        public static string encodeSequence(string[] encodedPieces) {
            int totalLengthLen = 0;
            foreach(string piece in encodedPieces) {
                totalLengthLen += piece.Length;
            }
            return hex0 + encodeLength(totalLengthLen) + string.Join("", encodedPieces);
        }

        public static string encodeInteger(BigInteger x) {
            if (x < 0) {
                throw new ArgumentException("x cannot be negative");
            }

            string t = x.ToString("X");

            if (t.Length % 2 == 1) {
                t = "0" + t;
            }

            string xString = BinaryAscii.binaryFromHex(t);

            int num = xString[0];

            if (num <= hex127) {
                return hexB + Convert.ToChar(xString.Length) + hexAt + xString;
            }

            return hexB + Convert.ToChar(xString.Length + 1) + hexAt + x;

        }

        public static string encodeOid(int[] oid) {
            int first = oid[0];
            int second = oid[1];

            if (first > 2) {
                throw new ArgumentException("first has to be <= 2");
            }

            if (second > 39) {
                throw new ArgumentException("second has to be <= 39");
            }

            string body = Convert.ToChar(40 * first + second).ToString();
            for (int i=2; i < oid.Length; i++) {
                body += encodeNumber(oid[i]);
            }

            return hexF + encodeLength(body.Length) + body;
        }

        public static string encodeBitString(string t) {
            return hexC + encodeLength(t.Length) + t;
        }

        public static string encodeOctetString(string t) {
            return hexD + encodeLength(t.Length) + t;
        }

        public static string encodeConstructed(int tag, string value) {
            return Convert.ToChar(hex129 + tag) + encodeLength(value.Length) + value;
        }

        public static Tuple<string, string> removeSequence(string str) {
            checkSequenceError(str, bytesHexB, "02");

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            int endSeq = 1 + lengthLen + length;

            return new Tuple<string, string> (
                str.Substring(1 + lengthLen, length),
                str.Substring(endSeq)
            );
        }

        public static Tuple<BigInteger, string> removeInteger(string str) {
            checkSequenceError(str, bytesHexB, "02");

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            string numberBytes = str.Substring(1 + lengthLen, length);
            string rest = str.Substring(1 + lengthLen + length);
            int nBytes = numberBytes[0];

            if (nBytes >= hex160) {
                throw new ArgumentException("nBytes must be < 160");
            }

            return new Tuple<BigInteger, string> (
                BinaryAscii.numberFromHex(BinaryAscii.hexFromBinary(numberBytes)),
                rest
            );

        }

        public static Tuple<int[], string> removeObject(string str) {
            checkSequenceError(str, bytesHexF, "06");

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            string body = str.Substring(1 + lengthLen, length);
            string rest = str.Substring(1 + lengthLen + length);

            List<int> numbers = new List<int>();
            Tuple<int, int> readNumberResult;
            while (body.Length > 0) {
                readNumberResult = readNumber(body);
                numbers.Add(readNumberResult.Item1);
                body = body.Substring(readNumberResult.Item2);
            }

            int n0 = numbers[0];
            numbers.RemoveAt(0);

            int first = n0 / 40;
            int second = n0 - (40 * first);
            numbers.Insert(0, first);
            numbers.Insert(1, second);

            return new Tuple<int[], string> (
                numbers.ToArray(),
                rest
            );
        }

        public static Tuple<string, string> removeBitString(string str) {
            checkSequenceError(str, bytesHexC, "03");

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            string body = str.Substring(1 + lengthLen, length);
            string rest = str.Substring(1 + lengthLen + length);

            return new Tuple<string, string>(body, rest);
        }

        public static Tuple<string, string> removeOctetString(string str) {
            checkSequenceError(str, bytesHexD, "04");

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            string body = str.Substring(1 + lengthLen, length);
            string rest = str.Substring(1 + lengthLen + length);

            return new Tuple<string, string>(body, rest);
        }

        public static Tuple<int, string, string> removeConstructed(string str) {
            int s0 = extractFirstInt(str);

            if ((s0 & hex224) != hex129) {
                throw new ArgumentException("wanted constructed tag (0xa0-0xbf), got " + s0);
            }

            int tag = s0 & hex31;

            Tuple<int, int> readLengthResult = readLength(str.Substring(1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            string body = str.Substring(1 + lengthLen, length);
            string rest = str.Substring(1 + lengthLen + length);

            return new Tuple<int, string, string>(tag, body, rest);
        }

        public static string fromPem(string pem) {
            string[] split = pem.Split("\n");
            List<string> stripped = new List<string>();

            for (int i = 0; i < split.Length; i++) {
                string line = split[i].Trim();
                if (line.Substring(0, 5) != "-----") {
                    stripped.Add(line);
                }
            }

            return Base64.decode(string.Join("", stripped));
        }

        public static string toPem(string der, string name) {
            string b64 = Base64.encode(der);
            List<string> lines = new List<string> { "-----BEGIN " + name + "-----" };

            int strLength = b64.Length;
            for (int i = 0; i < strLength; i += 64)
            {
                lines.Add(b64.Substring(i, 64));
            }
            lines.Add("-----END " + name + "-----");

            return string.Join("\n", lines);

        }

        private static string encodeLength(int length) {
            if (length < 0) {
                throw new ArgumentException("length cannot be negative");
            }

            if (length < hex160) {
                return ((char)length).ToString();
            }

            string s = length.ToString("X");
            if ((s.Length % 2) == 1) {
                s = "0" + s;
            }

            s = BinaryAscii.binaryFromHex(s);
            int lengthLen = s.Length;

            return ((char)(hex160 | lengthLen)) + s;
        }

        private static string encodeNumber(int n) {
            List<int> b128Digits = new List<int>();

            while (n > 0) {
                b128Digits.Insert(0, (n & hex127) | hex160);
                n >>= 7;
            }

            int b128DigitsCount = b128Digits.Count;

            if (b128DigitsCount == 0) {
                b128Digits.Add(0);
                b128DigitsCount++;
            }

            b128Digits[b128DigitsCount - 1] &= hex127;

            string join = "";

            for (int i=0; i < b128DigitsCount; i++) {
                join += (char)b128Digits[i];
            }

            return join;
        }

        private static Tuple<int, int> readLength(string str) {
            int num = extractFirstInt(str);

            if ((num & hex160) == 0) {
                return new Tuple<int, int>(num & hex127, 1);
            }

            int lengthLen = num & hex127;

            if (lengthLen > str.Length - 1) {
                throw new ArgumentException("ran out of length bytes");
            }

            return new Tuple<int, int>(
                int.Parse(
                    BinaryAscii.hexFromBinary(str.Substring(1, lengthLen)),
                    System.Globalization.NumberStyles.HexNumber
                ),
                1 + lengthLen
            );
        }

        private static Tuple<int, int> readNumber(string str) {
            int number = 0;
            int lengthLen = 0;
            int d;

            while (true) {
                if (lengthLen > str.Length) {
                    throw new ArgumentException("ran out of length bytes");
                }

                number <<= 7;
                d = str[lengthLen];
                number += (d & hex127);
                lengthLen += 1;
                if ((d & hex160) == 0) {
                    break;
                }
            }

            return new Tuple<int, int>(number, lengthLen);
        }

        private static void checkSequenceError(string str, string start, string expected) {
            if (str.Substring(0, start.Length) != start) {
                throw new ArgumentException(
                    "wanted sequence (" +
                    expected +
                    "), got " +
                    extractFirstInt(str)
                );
            }
        }

        private static int extractFirstInt(string str) {
            return (int)str[0];
        }
    }
}
