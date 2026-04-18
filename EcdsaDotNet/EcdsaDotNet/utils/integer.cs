using System;
using System.Numerics;
using System.Security.Cryptography;

namespace EllipticCurve.Utils {

    public static class Integer {
        public static BigInteger modulo(BigInteger dividend, BigInteger divisor) {
            BigInteger remainder = BigInteger.Remainder(dividend, divisor);

            if (remainder < 0) {
                return remainder + divisor;
            }

            return remainder;
        }

        public static int bitLength(BigInteger value) {
            if (value < 0) {
                value = -value;
            }
            if (value.IsZero) {
                return 0;
            }
            byte[] bytes = value.ToByteArray();
            int byteCount = bytes.Length;
            byte highByte = bytes[byteCount - 1];
            // The last byte may be a sign byte (0x00) for positive numbers
            if (highByte == 0 && byteCount > 1) {
                byteCount--;
                highByte = bytes[byteCount - 1];
            }
            int bits = (byteCount - 1) * 8;
            while (highByte > 0) {
                bits++;
                highByte >>= 1;
            }
            return bits;
        }

        public static BigInteger randomBetween(BigInteger minimum, BigInteger maximum) {
            if (maximum < minimum) {
                throw new ArgumentException("maximum must be greater than minimum");
            }

            BigInteger range = maximum - minimum;

            Tuple<int, BigInteger> response = calculateParameters(range);
            int bytesNeeded = response.Item1;
            BigInteger mask = response.Item2;

            byte[] randomBytes = new byte[bytesNeeded];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(randomBytes);
            }

            BigInteger randomValue = new BigInteger(randomBytes);

            /* We apply the mask to reduce the amount of attempts we might need
                * to make to get a number that is in range. This is somewhat like
                * the commonly used 'modulo trick', but without the bias:
                *
                *   "Let's say you invoke secure_rand(0, 60). When the other code
                *    generates a random integer, you might get 243. If you take
                *    (243 & 63)-- noting that the mask is 63-- you get 51. Since
                *    51 is less than 60, we can return this without bias. If we
                *    got 255, then 255 & 63 is 63. 63 > 60, so we try again.
                *
                *    The purpose of the mask is to reduce the number of random
                *    numbers discarded for the sake of ensuring an unbiased
                *    distribution. In the example above, 243 would discard, but
                *    (243 & 63) is in the range of 0 and 60."
                *
                *   (Source: Scott Arciszewski)
                */

            randomValue &= mask;

            if (randomValue <= range) {
                /* We've been working with 0 as a starting point, so we need to
                    * add the `minimum` here. */
                return minimum + randomValue;
            }

            /* Outside of the acceptable range, throw it away and try again.
                * We don't try any modulo tricks, as this would introduce bias. */
            return randomBetween(minimum, maximum);

        }

        private static Tuple<int, BigInteger> calculateParameters(BigInteger range) {
            int bitsNeeded = 0;
            int bytesNeeded = 0;
            BigInteger mask = new BigInteger(1);

            while (range > 0) {
                if (bitsNeeded % 8 == 0) {
                    bytesNeeded += 1;
                }

                bitsNeeded++;

                mask = (mask << 1) | 1;

                range >>= 1;
            }

            return Tuple.Create(bytesNeeded, mask);

        }

        public static byte[] rfc6979(byte[] hashBytes, BigInteger secret, CurveFp curve, string hashfunc, int hashLen) {
            // Generate nonce values per hedged RFC 6979 §3.6: deterministic k
            // derivation with fresh random entropy mixed into K-init. Same
            // message and key yield different signatures, while preserving
            // RFC 6979's protection against RNG failures.
            // Returns byte[] representing the first valid k.

            int orderBitLen = bitLength(curve.N);
            int orderByteLen = (orderBitLen + 7) / 8;

            byte[] secretBytes = bigIntToBytes(secret, orderByteLen);

            BigInteger hashReduced = modulo(numberFromBytesBE(hashBytes, orderBitLen), curve.N);
            byte[] hashOctets = bigIntToBytes(hashReduced, orderByteLen);

            byte[] extraEntropy = new byte[orderByteLen];
            using (var rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(extraEntropy);
            }

            byte[] V = new byte[hashLen];
            for (int i = 0; i < hashLen; i++) V[i] = 0x01;
            byte[] K = new byte[hashLen];

            K = hmacCompute(hashfunc, K, concat(V, new byte[] { 0x00 }, secretBytes, hashOctets, extraEntropy));
            V = hmacCompute(hashfunc, K, V);
            K = hmacCompute(hashfunc, K, concat(V, new byte[] { 0x01 }, secretBytes, hashOctets, extraEntropy));
            V = hmacCompute(hashfunc, K, V);

            while (true) {
                byte[] T = new byte[0];
                while (T.Length * 8 < orderBitLen) {
                    V = hmacCompute(hashfunc, K, V);
                    T = concat(T, V);
                }

                BigInteger k = numberFromBytesBE(T, orderBitLen);

                if (k >= 1 && k <= curve.N - 1) {
                    return bigIntToBytes(k, orderByteLen);
                }

                K = hmacCompute(hashfunc, K, concat(V, new byte[] { 0x00 }));
                V = hmacCompute(hashfunc, K, V);
            }
        }

        public static BigInteger numberFromBytesBE(byte[] bytes, int bitLength) {
            // Convert big-endian bytes to BigInteger with hash truncation
            string hex = BinaryAscii.hexFromBinary(bytes);
            BigInteger number = BinaryAscii.numberFromHex(hex);
            int hashBitLen = bytes.Length * 8;
            if (hashBitLen > bitLength) {
                number >>= (hashBitLen - bitLength);
            }
            return number;
        }

        public static byte[] bigIntToBytes(BigInteger value, int length) {
            string hex = BinaryAscii.hexFromNumber(value, length);
            return BinaryAscii.binaryFromHex(hex);
        }

        public static byte[] hmacCompute(string hashfunc, byte[] key, byte[] data) {
            HMAC hmacAlg = null;
            switch (hashfunc.ToLower()) {
                case "sha256":
                    hmacAlg = new HMACSHA256(key);
                    break;
                case "sha384":
                    hmacAlg = new HMACSHA384(key);
                    break;
                case "sha512":
                    hmacAlg = new HMACSHA512(key);
                    break;
                case "sha1":
                    hmacAlg = new HMACSHA1(key);
                    break;
                default:
                    throw new ArgumentException("Unsupported hash function: " + hashfunc);
            }
            using (hmacAlg) {
                return hmacAlg.ComputeHash(data);
            }
        }

        internal static byte[] concat(params byte[][] arrays) {
            int totalLength = 0;
            foreach (byte[] arr in arrays) {
                totalLength += arr.Length;
            }
            byte[] result = new byte[totalLength];
            int offset = 0;
            foreach (byte[] arr in arrays) {
                Array.Copy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            return result;
        }

    }

}
