using System.Collections.Generic;
using System.Numerics;
using System;

namespace EllipticCurve.Utils {

    public static class Der {

        private static readonly int hex31 = 0x1f;
        private static readonly int hex127 = 0x7f;
        private static readonly int hex128 = 0x80;
        private static readonly int hex160 = 0xa0;
        private static readonly int hex224 = 0xe0;

        private static readonly string hexAt = "00";
        private static readonly string hexB = "02";
        private static readonly string hexC = "03";
        private static readonly string hexD = "04";
        private static readonly string hexF = "06";
        private static readonly string hex0 = "30";

        private static readonly byte[] bytesHexAt = BinaryAscii.binaryFromHex(hexAt);
        private static readonly byte[] bytesHexB = BinaryAscii.binaryFromHex(hexB);
        private static readonly byte[] bytesHexC = BinaryAscii.binaryFromHex(hexC);
        private static readonly byte[] bytesHexD = BinaryAscii.binaryFromHex(hexD);
        private static readonly byte[] bytesHexF = BinaryAscii.binaryFromHex(hexF);
        private static readonly byte[] bytesHex0 = BinaryAscii.binaryFromHex(hex0);

        public static byte[] encodeSequence(List<byte[]> encodedPieces) {
            int totalLengthLen = 0;
            foreach(byte[] piece in encodedPieces) {
                totalLengthLen += piece.Length;
            }
            List<byte[]> sequence = new List<byte[]> { bytesHex0, encodeLength(totalLengthLen) };
            sequence.AddRange(encodedPieces);
            return combineByteArrays(sequence);
        }

        public static byte[] encodeInteger(BigInteger x) {
            if (x < 0) {
                throw new ArgumentException("x cannot be negative");
            }

            string t = x.ToString("X");

            if (t.Length % 2 == 1) {
                t = "0" + t;
            }

            byte[] xBytes = BinaryAscii.binaryFromHex(t);

            int num = xBytes[0];

            if (num <= hex127) {
                return combineByteArrays(new List<byte[]> {
                    bytesHexB,
                    Bytes.intToCharBytes(xBytes.Length),
                    xBytes
                });
            }

            return combineByteArrays(new List<byte[]> {
                bytesHexB,
                Bytes.intToCharBytes(xBytes.Length + 1),
                bytesHexAt,
                xBytes
            });

        }

        public static byte[] encodeOid(int[] oid) {
            int first = oid[0];
            int second = oid[1];

            if (first > 2) {
                throw new ArgumentException("first has to be <= 2");
            }

            if (second > 39) {
                throw new ArgumentException("second has to be <= 39");
            }

            List<byte[]> bodyList = new List<byte[]> {
                Bytes.intToCharBytes(40 * first + second)
            };

            for (int i=2; i < oid.Length; i++) {
                bodyList.Add(encodeNumber(oid[i]));
            }

            byte[] body = combineByteArrays(bodyList);

            return combineByteArrays( new List<byte[]> {
                bytesHexF,
                encodeLength(body.Length),
                body
            });

        }

        public static byte[] encodeBitString(byte[] t) {
            return combineByteArrays(new List<byte[]> {
                bytesHexC,
                encodeLength(t.Length),
                t
            });
        }

        public static byte[] encodeOctetString(byte[] t) {
            return combineByteArrays(new List<byte[]> {
                bytesHexD,
                encodeLength(t.Length),
                t
            });
        }

        public static byte[] encodeConstructed(int tag, byte[] value) {
            return combineByteArrays(new List<byte[]> {
                Bytes.intToCharBytes(hex160 + tag),
                encodeLength(value.Length),
                value
            });
        }

        public static Tuple<byte[], byte[]> removeSequence(byte[] bytes) {
            checkSequenceError(bytes, hex0, "30");

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            int endSeq = 1 + lengthLen + length;

            return new Tuple<byte[], byte[]>(
                Bytes.sliceByteArray(bytes, 1 + lengthLen, length),
                Bytes.sliceByteArray(bytes, endSeq)
            );
        }

        public static Tuple<BigInteger, byte[]> removeInteger(byte[] bytes) {
            checkSequenceError(bytes, hexB, "02");

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            byte[] numberBytes = Bytes.sliceByteArray(bytes, 1 + lengthLen, length);
            byte[] rest = Bytes.sliceByteArray(bytes, 1 + lengthLen + length);
            int nBytes = numberBytes[0];

            if (nBytes >= hex128) {
                throw new ArgumentException("first byte of integer must be < 128");
            }

            return new Tuple<BigInteger, byte[]> (
                BinaryAscii.numberFromHex(BinaryAscii.hexFromBinary(numberBytes)),
                rest
            );

        }

        public static Tuple<int[], byte[]> removeObject(byte[] bytes) {
            checkSequenceError(bytes, hexF, "06");

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            byte[] body = Bytes.sliceByteArray(bytes, 1 + lengthLen, length);
            byte[] rest = Bytes.sliceByteArray(bytes, 1 + lengthLen + length);

            List<int> numbers = new List<int>();
            Tuple<int, int> readNumberResult;
            while (body.Length > 0) {
                readNumberResult = readNumber(body);
                numbers.Add(readNumberResult.Item1);
                body = Bytes.sliceByteArray(body, readNumberResult.Item2);
            }

            int n0 = numbers[0];
            numbers.RemoveAt(0);

            int first = n0 / 40;
            int second = n0 - (40 * first);
            numbers.Insert(0, first);
            numbers.Insert(1, second);

            return new Tuple<int[], byte[]> (
                numbers.ToArray(),
                rest
            );
        }

        public static Tuple<byte[], byte[]> removeBitString(byte[] bytes) {
            checkSequenceError(bytes, hexC, "03");

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            byte[] body = Bytes.sliceByteArray(bytes, 1 + lengthLen, length);
            byte[] rest = Bytes.sliceByteArray(bytes, 1 + lengthLen + length);

            return new Tuple<byte[], byte[]>(body, rest);
        }

        public static Tuple<byte[], byte[]> removeOctetString(byte[] bytes) {
            checkSequenceError(bytes, hexD, "04");

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            byte[] body = Bytes.sliceByteArray(bytes, 1 + lengthLen, length);
            byte[] rest = Bytes.sliceByteArray(bytes, 1 + lengthLen + length);

            return new Tuple<byte[], byte[]>(body, rest);
        }

        public static Tuple<int, byte[], byte[]> removeConstructed(byte[] bytes) {
            int s0 = extractFirstInt(bytes);

            if ((s0 & hex224) != hex160) {
                throw new ArgumentException("wanted constructed tag (0xa0-0xbf), got " + s0);
            }

            int tag = s0 & hex31;

            Tuple<int, int> readLengthResult = readLength(Bytes.sliceByteArray(bytes, 1));
            int length = readLengthResult.Item1;
            int lengthLen = readLengthResult.Item2;

            byte[] body = Bytes.sliceByteArray(bytes, 1 + lengthLen, length);
            byte[] rest = Bytes.sliceByteArray(bytes, 1 + lengthLen + length);

            return new Tuple<int, byte[], byte[]>(tag, body, rest);
        }

        public static byte[] fromPem(string pem) {
            string[] split = pem.Split(new string[] { "\n" }, StringSplitOptions.None);
            List<string> stripped = new List<string>();

            for (int i = 0; i < split.Length; i++) {
                string line = split[i].Trim();
                if (String.substring(line, 0, 5) != "-----") {
                    stripped.Add(line);
                }
            }

            return Base64.decode(string.Join("", stripped));
        }

        public static string toPem(byte[] der, string name) {
            string b64 = Base64.encode(der);
            List<string> lines = new List<string> { "-----BEGIN " + name + "-----" };

            int strLength = b64.Length;
            for (int i = 0; i < strLength; i += 64)
            {
                lines.Add(String.substring(b64, i, 64));
            }
            lines.Add("-----END " + name + "-----");

            return string.Join("\n", lines);
        }

        public static byte[] combineByteArrays(List<byte[]> byteArrayList) {
            int totalLength = 0;
            foreach (byte[] bytes in byteArrayList)
            {
                totalLength += bytes.Length;
            }

            byte[] combined = new byte[totalLength];
            int consumedLength = 0;

            foreach (byte[] bytes in byteArrayList)
            {
                Array.Copy(bytes, 0, combined, consumedLength, bytes.Length);
                consumedLength += bytes.Length;
            }

            return combined;
        }

        private static byte[] encodeLength(int length) {
            if (length < 0) {
                throw new ArgumentException("length cannot be negative");
            }

            if (length < hex128) {
                return Bytes.intToCharBytes(length);
            }

            string s = length.ToString("X");
            if ((s.Length % 2) == 1) {
                s = "0" + s;
            }

            byte[] bytes = BinaryAscii.binaryFromHex(s);
            int lengthLen = bytes.Length;

            return combineByteArrays(new List<byte[]> {
                Bytes.intToCharBytes(hex128 | lengthLen),
                bytes
            });
        }

        private static byte[] encodeNumber(int n) {
            List<int> b128Digits = new List<int>();

            while (n > 0) {
                b128Digits.Insert(0, (n & hex127) | hex128);
                n >>= 7;
            }

            int b128DigitsCount = b128Digits.Count;

            if (b128DigitsCount == 0) {
                b128Digits.Add(0);
                b128DigitsCount++;
            }

            b128Digits[b128DigitsCount - 1] &= hex127;

            List<byte[]> byteList = new List<byte[]>();

            foreach(int digit in b128Digits) {
                byteList.Add(Bytes.intToCharBytes(digit));
            }

            return combineByteArrays(byteList);
        }

        private static Tuple<int, int> readLength(byte[] bytes) {
            int num = extractFirstInt(bytes);

            if ((num & hex128) == 0) {
                return new Tuple<int, int>(num & hex127, 1);
            }

            int lengthLen = num & hex127;

            if (lengthLen > bytes.Length - 1) {
                throw new ArgumentException("ran out of length bytes");
            }

            return new Tuple<int, int>(
                int.Parse(
                    BinaryAscii.hexFromBinary(Bytes.sliceByteArray(bytes, 1, lengthLen)),
                    System.Globalization.NumberStyles.HexNumber
                ),
                1 + lengthLen
            );
        }

        private static Tuple<int, int> readNumber(byte[] str) {
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
                if ((d & hex128) == 0) {
                    break;
                }
            }

            return new Tuple<int, int>(number, lengthLen);
        }

        private static void checkSequenceError(byte[] bytes, string start, string expected) {
            if (BinaryAscii.hexFromBinary(bytes).Substring(0, start.Length) != start) {
                throw new ArgumentException(
                    "wanted sequence " +
                    expected.Substring(0, 2) +
                    ", got " +
                    extractFirstInt(bytes).ToString("X")
                );
            }
        }

        private static int extractFirstInt(byte[] str) {
            return str[0];
        }

        
    }
}
