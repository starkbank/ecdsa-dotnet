using System.Numerics;
using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class Rfc6979KnownAnswerTest {
        // Test vectors from RFC 6979 Appendix A.2.5 (prime256v1/SHA-256).
        // The r values match the RFC exactly; s values are low-S normalized
        // (s = N - s when RFC s > N/2).

        private readonly PrivateKey privateKey;
        private readonly PublicKey publicKey;

        public Rfc6979KnownAnswerTest() {
            privateKey = new PrivateKey(
                Curves.prime256v1,
                EllipticCurve.Utils.BinaryAscii.numberFromHex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            );
            publicKey = privateKey.publicKey();
        }

        [Fact]
        public void testPublicKeyMatchesRfc() {
            Assert.Equal(
                publicKey.point.x,
                EllipticCurve.Utils.BinaryAscii.numberFromHex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
            );
            Assert.Equal(
                publicKey.point.y,
                EllipticCurve.Utils.BinaryAscii.numberFromHex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
            );
        }

        [Fact]
        public void testSampleMessageSignature() {
            Signature sig = Ecdsa.sign("sample", privateKey);
            // r matches RFC 6979 A.2.5 exactly
            Assert.Equal(sig.r, EllipticCurve.Utils.BinaryAscii.numberFromHex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"));
            // s is low-S normalized: N - 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
            Assert.Equal(sig.s, EllipticCurve.Utils.BinaryAscii.numberFromHex("0834E36AD29A83BF2BC9385E491D6099C8FDF9D1ED67AA7EA5F51F93782857A9"));
            Assert.True(Ecdsa.verify("sample", sig, publicKey));
        }

        [Fact]
        public void testTestMessageSignature() {
            Signature sig = Ecdsa.sign("test", privateKey);
            // r matches RFC 6979 A.2.5 exactly
            Assert.Equal(sig.r, EllipticCurve.Utils.BinaryAscii.numberFromHex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"));
            // s already low-S, matches RFC directly
            Assert.Equal(sig.s, EllipticCurve.Utils.BinaryAscii.numberFromHex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"));
            Assert.True(Ecdsa.verify("test", sig, publicKey));
        }
    }

    public class Secp256k1KnownAnswerTest {
        // Known-answer tests for secp256k1 with secret=1 (pubkey = generator G).

        private readonly PrivateKey privateKey;
        private readonly PublicKey publicKey;

        public Secp256k1KnownAnswerTest() {
            privateKey = new PrivateKey(Curves.secp256k1, 1);
            publicKey = privateKey.publicKey();
        }

        [Fact]
        public void testPublicKeyIsGenerator() {
            Assert.Equal(publicKey.point.x, Curves.secp256k1.G.x);
            Assert.Equal(publicKey.point.y, Curves.secp256k1.G.y);
        }

        [Fact]
        public void testSampleMessageSignature() {
            Signature sig = Ecdsa.sign("sample", privateKey);
            Assert.Equal(sig.r, EllipticCurve.Utils.BinaryAscii.numberFromHex("58DB657BCD631038BEA07B4941172F0167ACA98F12B55E3176BD1C35435D6501"));
            Assert.Equal(sig.s, EllipticCurve.Utils.BinaryAscii.numberFromHex("3A78E73D8FF8AB554E13C10F6390D81A882F91945D6275493882676170B53A57"));
            Assert.True(Ecdsa.verify("sample", sig, publicKey));
        }

        [Fact]
        public void testTestMessageSignature() {
            Signature sig = Ecdsa.sign("test", privateKey);
            Assert.Equal(sig.r, EllipticCurve.Utils.BinaryAscii.numberFromHex("98DF3AAED18D1299109E9732E3015F7E68E5D1FDEAD6924809B410D970A3B0CE"));
            Assert.Equal(sig.s, EllipticCurve.Utils.BinaryAscii.numberFromHex("3EF15987C6592379BAAD6392586A382D63952572632FCD951AE75E7471C144C6"));
            Assert.True(Ecdsa.verify("test", sig, publicKey));
        }
    }

    public class MalleabilityTest {

        [Fact]
        public void testSignAlwaysProducesLowS() {
            for (int i = 0; i < 100; i++) {
                PrivateKey privateKey = new PrivateKey();
                Signature signature = Ecdsa.sign("test message", privateKey);
                Assert.True(signature.s <= privateKey.curve.N / 2);
            }
        }

        [Fact]
        public void testHighSSignatureStillVerifies() {
            // verify() accepts high-s for OpenSSL compatibility; sign() prevents malleability
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);
            Signature highS = new Signature(signature.r, privateKey.curve.N - signature.s);

            Assert.True(Ecdsa.verify(message, signature, publicKey));
            Assert.True(Ecdsa.verify(message, highS, publicKey));
        }
    }

    public class PublicKeyValidationTest {

        [Fact]
        public void testRejectOffCurvePublicKey() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);

            Point offCurvePoint = new Point(publicKey.point.x, publicKey.point.y + 1);
            PublicKey offCurveKey = new PublicKey(offCurvePoint, publicKey.curve);

            Assert.False(Ecdsa.verify(message, signature, offCurveKey));
        }

        [Fact]
        public void testFromStringRejectsOffCurvePoint() {
            PrivateKey p = new PrivateKey();
            PublicKey pub = p.publicKey();
            string badY = EllipticCurve.Utils.BinaryAscii.hexFromNumber(pub.point.y + 1, pub.curve.length());
            string badHex = EllipticCurve.Utils.BinaryAscii.hexFromNumber(pub.point.x, pub.curve.length()) + badY;
            byte[] badBytes = EllipticCurve.Utils.BinaryAscii.binaryFromHex(badHex);
            Assert.Throws<System.ArgumentException>(() => PublicKey.fromString(badBytes, pub.curve));
        }

        [Fact]
        public void testFromStringRejectsInfinityPoint() {
            int len = Curves.secp256k1.length();
            byte[] zeroBytes = new byte[2 * len];
            Assert.Throws<System.ArgumentException>(() => PublicKey.fromString(zeroBytes, Curves.secp256k1));
        }
    }

    public class ForgeryAttemptTest {

        private readonly PrivateKey privateKey;
        private readonly PublicKey publicKey;
        private readonly string message;
        private readonly Signature signature;

        public ForgeryAttemptTest() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
            message = "authentic message";
            signature = Ecdsa.sign(message, privateKey);
        }

        [Fact]
        public void testRejectZeroSignature() {
            Assert.False(Ecdsa.verify(message, new Signature(0, 0), publicKey));
        }

        [Fact]
        public void testRejectREqualsZero() {
            Assert.False(Ecdsa.verify(message, new Signature(0, signature.s), publicKey));
        }

        [Fact]
        public void testRejectSEqualsZero() {
            Assert.False(Ecdsa.verify(message, new Signature(signature.r, 0), publicKey));
        }

        [Fact]
        public void testRejectREqualsN() {
            BigInteger N = publicKey.curve.N;
            Assert.False(Ecdsa.verify(message, new Signature(N, signature.s), publicKey));
        }

        [Fact]
        public void testRejectSEqualsN() {
            BigInteger N = publicKey.curve.N;
            Assert.False(Ecdsa.verify(message, new Signature(signature.r, N), publicKey));
        }

        [Fact]
        public void testRejectRExceedsN() {
            BigInteger N = publicKey.curve.N;
            Assert.False(Ecdsa.verify(message, new Signature(N + 1, signature.s), publicKey));
        }

        [Fact]
        public void testRejectArbitrarySignature() {
            Assert.False(Ecdsa.verify(message, new Signature(1, 1), publicKey));
        }

        [Fact]
        public void testRejectBoundarySignature() {
            BigInteger N = publicKey.curve.N;
            Assert.False(Ecdsa.verify(message, new Signature(N - 1, N - 1), publicKey));
        }

        [Fact]
        public void testWrongKeyRejected() {
            PublicKey otherKey = new PrivateKey().publicKey();
            Assert.False(Ecdsa.verify(message, signature, otherKey));
        }
    }

    public class Rfc6979Test {

        [Fact]
        public void testDeterministicSignature() {
            PrivateKey privateKey = new PrivateKey();
            string message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey);
            Signature signature2 = Ecdsa.sign(message, privateKey);

            Assert.Equal(signature1.r, signature2.r);
            Assert.Equal(signature1.s, signature2.s);
        }

        [Fact]
        public void testDifferentMessagesDifferentSignatures() {
            PrivateKey privateKey = new PrivateKey();

            Signature signature1 = Ecdsa.sign("message 1", privateKey);
            Signature signature2 = Ecdsa.sign("message 2", privateKey);

            Assert.True(signature1.r != signature2.r || signature1.s != signature2.s);
        }

        [Fact]
        public void testDifferentKeysDifferentSignatures() {
            string message = "test message";

            Signature signature1 = Ecdsa.sign(message, new PrivateKey());
            Signature signature2 = Ecdsa.sign(message, new PrivateKey());

            Assert.True(signature1.r != signature2.r || signature1.s != signature2.s);
        }
    }

    public class EdgeCaseMessageTest {

        private readonly PrivateKey privateKey;
        private readonly PublicKey publicKey;

        public EdgeCaseMessageTest() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
        }

        private void signAndVerify(string message) {
            Signature sig = Ecdsa.sign(message, privateKey);
            Assert.True(Ecdsa.verify(message, sig, publicKey));
            Assert.False(Ecdsa.verify(message + "x", sig, publicKey));
        }

        [Fact]
        public void testEmptyMessage() {
            signAndVerify("");
        }

        [Fact]
        public void testSingleCharMessage() {
            signAndVerify("a");
        }

        [Fact]
        public void testUnicodeMessage() {
            signAndVerify("\u00e9\u00e8\u00ea\u00eb");
        }

        [Fact]
        public void testEmojiMessage() {
            signAndVerify("\U0001f512\U0001f511");
        }

        [Fact]
        public void testNullByteMessage() {
            signAndVerify("before\x00after");
        }

        [Fact]
        public void testLongMessage() {
            signAndVerify(new string('a', 10000));
        }

        [Fact]
        public void testNewlinesAndWhitespace() {
            signAndVerify("  line1\n\tline2\r\n  ");
        }
    }

    public class SerializationRoundTripTest {

        private readonly PrivateKey privateKey;
        private readonly PublicKey publicKey;
        private readonly string message;
        private readonly Signature signature;

        public SerializationRoundTripTest() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
            message = "round-trip test";
            signature = Ecdsa.sign(message, privateKey);
        }

        [Fact]
        public void testSignatureDerRoundTrip() {
            byte[] der = signature.toDer();
            Signature restored = Signature.fromDer(der);
            Assert.Equal(restored.r, signature.r);
            Assert.Equal(restored.s, signature.s);
            Assert.True(Ecdsa.verify(message, restored, publicKey));
        }

        [Fact]
        public void testSignatureBase64RoundTrip() {
            string b64 = signature.toBase64();
            Signature restored = Signature.fromBase64(b64);
            Assert.Equal(restored.r, signature.r);
            Assert.Equal(restored.s, signature.s);
            Assert.True(Ecdsa.verify(message, restored, publicKey));
        }

        [Fact]
        public void testSignatureDerWithRecoveryIdRoundTrip() {
            byte[] der = signature.toDer(withRecoveryId: true);
            Signature restored = Signature.fromDer(der, recoveryByte: true);
            Assert.Equal(restored.r, signature.r);
            Assert.Equal(restored.s, signature.s);
            Assert.Equal(restored.recoveryId, signature.recoveryId);
        }

        [Fact]
        public void testPrivateKeyPemRoundTrip() {
            string pem = privateKey.toPem();
            PrivateKey restored = PrivateKey.fromPem(pem);
            Assert.Equal(restored.secret, privateKey.secret);
            Assert.Equal(restored.curve.name, privateKey.curve.name);
        }

        [Fact]
        public void testPrivateKeyDerRoundTrip() {
            byte[] der = privateKey.toDer();
            PrivateKey restored = PrivateKey.fromDer(der);
            Assert.Equal(restored.secret, privateKey.secret);
        }

        [Fact]
        public void testPublicKeyPemRoundTrip() {
            string pem = publicKey.toPem();
            PublicKey restored = PublicKey.fromPem(pem);
            Assert.Equal(restored.point.x, publicKey.point.x);
            Assert.Equal(restored.point.y, publicKey.point.y);
        }

        [Fact]
        public void testPublicKeyCompressedRoundTrip() {
            string compressed = publicKey.toCompressed();
            PublicKey restored = PublicKey.fromCompressed(compressed, publicKey.curve);
            Assert.Equal(restored.point.x, publicKey.point.x);
            Assert.Equal(restored.point.y, publicKey.point.y);
            Assert.True(Ecdsa.verify(message, signature, restored));
        }

        [Fact]
        public void testPublicKeyCompressedEvenAndOdd() {
            // Ensure both even-y and odd-y keys round-trip through compression
            for (int i = 0; i < 20; i++) {
                PrivateKey pk = new PrivateKey();
                PublicKey pub = pk.publicKey();
                string compressed = pub.toCompressed();
                PublicKey restored = PublicKey.fromCompressed(compressed, pub.curve);
                Assert.Equal(restored.point.x, pub.point.x);
                Assert.Equal(restored.point.y, pub.point.y);
            }
        }

        [Fact]
        public void testPrime256v1KeyRoundTrip() {
            PrivateKey pk = new PrivateKey(Curves.prime256v1);
            string pem = pk.toPem();
            PrivateKey restored = PrivateKey.fromPem(pem);
            Assert.Equal(restored.secret, pk.secret);
            Assert.Equal(restored.curve.name, "prime256v1");
        }
    }

    public class TonelliShanksTest {

        [Fact]
        public void testPrimeCongruent1Mod4() {
            // P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
            BigInteger P = 17;
            for (int value = 1; value < 17; value++) {
                if (BigInteger.ModPow(value, (P - 1) / 2, P) == 1) {
                    BigInteger root = EcdsaMath.modularSquareRoot(value, P);
                    Assert.Equal(EllipticCurve.Utils.Integer.modulo(root * root, P), (BigInteger)value);
                }
            }
        }

        [Fact]
        public void testPrimeCongruent5Mod8() {
            // P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
            BigInteger P = 13;
            for (int value = 1; value < 13; value++) {
                if (BigInteger.ModPow(value, (P - 1) / 2, P) == 1) {
                    BigInteger root = EcdsaMath.modularSquareRoot(value, P);
                    Assert.Equal(EllipticCurve.Utils.Integer.modulo(root * root, P), (BigInteger)value);
                }
            }
        }

        [Fact]
        public void testPrimeCongruent3Mod4() {
            // P = 7: fast path (S = 1)
            BigInteger P = 7;
            for (int value = 1; value < 7; value++) {
                if (BigInteger.ModPow(value, (P - 1) / 2, P) == 1) {
                    BigInteger root = EcdsaMath.modularSquareRoot(value, P);
                    Assert.Equal(EllipticCurve.Utils.Integer.modulo(root * root, P), (BigInteger)value);
                }
            }
        }

        [Fact]
        public void testZeroValue() {
            Assert.Equal(EcdsaMath.modularSquareRoot(0, 17), BigInteger.Zero);
        }
    }

    public class HashTruncationTest {

        [Fact]
        public void testSignVerifyWithSha512() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey, hashfunc: "sha512");

            Assert.True(Ecdsa.verify(message, signature, publicKey, hashfunc: "sha512"));
            Assert.False(Ecdsa.verify("wrong message", signature, publicKey, hashfunc: "sha512"));
        }

        [Fact]
        public void testSha512DeterministicSignature() {
            PrivateKey privateKey = new PrivateKey();
            string message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey, hashfunc: "sha512");
            Signature signature2 = Ecdsa.sign(message, privateKey, hashfunc: "sha512");

            Assert.Equal(signature1.r, signature2.r);
            Assert.Equal(signature1.s, signature2.s);
        }

        [Fact]
        public void testHashMismatchFails() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey, hashfunc: "sha256");
            Assert.False(Ecdsa.verify(message, signature, publicKey, hashfunc: "sha512"));
        }
    }

    public class Prime256v1SecurityTest {

        [Fact]
        public void testSignVerify() {
            PrivateKey privateKey = new PrivateKey(Curves.prime256v1);
            PublicKey publicKey = privateKey.publicKey();
            string message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);

            Assert.True(signature.s <= Curves.prime256v1.N / 2);
            Assert.True(Ecdsa.verify(message, signature, publicKey));
        }

        [Fact]
        public void testDeterministicSignature() {
            PrivateKey privateKey = new PrivateKey(Curves.prime256v1);
            string message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey);
            Signature signature2 = Ecdsa.sign(message, privateKey);

            Assert.Equal(signature1.r, signature2.r);
            Assert.Equal(signature1.s, signature2.s);
        }

        [Fact]
        public void testWrongCurveKeyFails() {
            // A signature made with secp256k1 should not verify with a prime256v1 key
            PrivateKey k1Key = new PrivateKey(Curves.secp256k1);
            PrivateKey p256Key = new PrivateKey(Curves.prime256v1);
            string message = "cross-curve test";

            Signature sig = Ecdsa.sign(message, k1Key);
            Assert.False(Ecdsa.verify(message, sig, p256Key.publicKey()));
        }
    }
}
