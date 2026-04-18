using System.Security.Cryptography;
using System.Numerics;
using System.Text;
using System;

namespace EllipticCurve {

    public static class Ecdsa {

        public static Signature sign(string message, PrivateKey privateKey, string hashfunc = "sha256") {
            CurveFp curve = privateKey.curve;
            byte[] byteMessage = computeHash(message, hashfunc);
            int orderBitLen = Utils.Integer.bitLength(curve.N);
            BigInteger numberMessage = Utils.Integer.numberFromBytesBE(byteMessage, orderBitLen);

            int hashLen = byteMessage.Length;
            int orderByteLen = (orderBitLen + 7) / 8;

            BigInteger r = BigInteger.Zero, s = BigInteger.Zero;
            Point randSignPoint = null;

            // Hedged RFC 6979 §3.6 HMAC-DRBG state: deterministic k derivation
            // with fresh random entropy mixed into K-init. Same message + key
            // yield different signatures, while preserving RFC 6979's protection
            // against RNG failures.
            byte[] secretBytes = Utils.Integer.bigIntToBytes(privateKey.secret, orderByteLen);
            BigInteger hashReduced = Utils.Integer.modulo(Utils.Integer.numberFromBytesBE(byteMessage, orderBitLen), curve.N);
            byte[] hashOctets = Utils.Integer.bigIntToBytes(hashReduced, orderByteLen);

            byte[] extraEntropy = new byte[orderByteLen];
            using (var rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(extraEntropy);
            }

            byte[] V = new byte[hashLen];
            for (int i = 0; i < hashLen; i++) V[i] = 0x01;
            byte[] K = new byte[hashLen];

            K = Utils.Integer.hmacCompute(hashfunc, K, Utils.Integer.concat(V, new byte[] { 0x00 }, secretBytes, hashOctets, extraEntropy));
            V = Utils.Integer.hmacCompute(hashfunc, K, V);
            K = Utils.Integer.hmacCompute(hashfunc, K, Utils.Integer.concat(V, new byte[] { 0x01 }, secretBytes, hashOctets, extraEntropy));
            V = Utils.Integer.hmacCompute(hashfunc, K, V);

            while (r.IsZero || s.IsZero) {
                byte[] T = new byte[0];
                while (T.Length * 8 < orderBitLen) {
                    V = Utils.Integer.hmacCompute(hashfunc, K, V);
                    T = Utils.Integer.concat(T, V);
                }

                BigInteger randNum = Utils.Integer.numberFromBytesBE(T, orderBitLen);

                if (randNum >= 1 && randNum <= curve.N - 1) {
                    randSignPoint = EcdsaMath.multiply(curve.G, randNum, curve.N, curve.A, curve.P);
                    r = Utils.Integer.modulo(randSignPoint.x, curve.N);
                    s = Utils.Integer.modulo(
                        (numberMessage + r * privateKey.secret) * EcdsaMath.inv(randNum, curve.N),
                        curve.N
                    );
                }

                if (r.IsZero || s.IsZero) {
                    K = Utils.Integer.hmacCompute(hashfunc, K, Utils.Integer.concat(V, new byte[] { 0x00 }));
                    V = Utils.Integer.hmacCompute(hashfunc, K, V);
                    r = BigInteger.Zero;
                    s = BigInteger.Zero;
                }
            }

            int recoveryId = (int)(randSignPoint.y & 1);
            if (randSignPoint.y > curve.N) {
                recoveryId += 2;
            }
            if (s > curve.N / 2) {
                s = curve.N - s;
                recoveryId ^= 1;
            }

            return new Signature(r, s, recoveryId);
        }

        public static bool verify(string message, Signature signature, PublicKey publicKey, string hashfunc = "sha256") {
            CurveFp curve = publicKey.curve;
            byte[] byteMessage = computeHash(message, hashfunc);
            int orderBitLen = Utils.Integer.bitLength(curve.N);
            BigInteger numberMessage = Utils.Integer.numberFromBytesBE(byteMessage, orderBitLen);

            BigInteger sigR = signature.r;
            BigInteger sigS = signature.s;

            if (sigR < 1 || sigR > curve.N - 1) {
                return false;
            }
            if (sigS < 1 || sigS > curve.N - 1) {
                return false;
            }
            if (!curve.contains(publicKey.point)) {
                return false;
            }

            BigInteger inv = EcdsaMath.inv(sigS, curve.N);

            Point v = EcdsaMath.multiplyAndAdd(
                curve.G,
                Utils.Integer.modulo(numberMessage * inv, curve.N),
                publicKey.point,
                Utils.Integer.modulo(sigR * inv, curve.N),
                curve.N,
                curve.A,
                curve.P
            );
            if (v.isAtInfinity()) {
                return false;
            }
            return Utils.Integer.modulo(v.x, curve.N) == sigR;
        }

        private static byte[] computeHash(string message, string hashfunc) {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            return computeHashBytes(messageBytes, hashfunc);
        }

        private static byte[] computeHashBytes(byte[] data, string hashfunc) {
            switch (hashfunc.ToLower()) {
                case "sha256": {
                    using (SHA256 sha256 = SHA256.Create()) {
                        return sha256.ComputeHash(data);
                    }
                }
                case "sha384": {
                    using (SHA384 sha384 = SHA384.Create()) {
                        return sha384.ComputeHash(data);
                    }
                }
                case "sha512": {
                    using (SHA512 sha512 = SHA512.Create()) {
                        return sha512.ComputeHash(data);
                    }
                }
                case "sha1": {
                    using (SHA1 sha1 = SHA1.Create()) {
                        return sha1.ComputeHash(data);
                    }
                }
                default:
                    throw new ArgumentException("Unsupported hash function: " + hashfunc);
            }
        }

    }

}
