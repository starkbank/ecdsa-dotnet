using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestCurve {

        [Fact]
        public void testSupportedCurve() {
            CurveFp newCurve = new CurveFp(
                EllipticCurve.Utils.BinaryAscii.numberFromHex("0000000000000000000000000000000000000000000000000000000000000000"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("0000000000000000000000000000000000000000000000000000000000000007"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
                "secp256k1",
                new int[] { 1, 3, 132, 0, 10 }
            );
            PrivateKey privateKey1 = new PrivateKey(newCurve);
            PublicKey publicKey1 = privateKey1.publicKey();

            string privateKeyPem = privateKey1.toPem();
            string publicKeyPem = publicKey1.toPem();

            PrivateKey privateKey2 = PrivateKey.fromPem(privateKeyPem);
            PublicKey publicKey2 = PublicKey.fromPem(publicKeyPem);

            string message = "test";

            string signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
            Signature signature = Signature.fromBase64(signatureBase64);

            Assert.True(Ecdsa.verify(message, signature, publicKey2));
        }

        [Fact]
        public void testAddNewCurve() {
            CurveFp newCurve = new CurveFp(
                EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb"),
                "frp256v1",
                new int[] { 1, 2, 250, 1, 223, 101, 256, 1 }
            );
            Curves.add(newCurve);
            PrivateKey privateKey1 = new PrivateKey(newCurve);
            PublicKey publicKey1 = privateKey1.publicKey();

            string privateKeyPem = privateKey1.toPem();
            string publicKeyPem = publicKey1.toPem();

            PrivateKey privateKey2 = PrivateKey.fromPem(privateKeyPem);
            PublicKey publicKey2 = PublicKey.fromPem(publicKeyPem);

            string message = "test";

            string signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
            Signature signature = Signature.fromBase64(signatureBase64);

            Assert.True(Ecdsa.verify(message, signature, publicKey2));
        }

        [Fact]
        public void testUnsupportedCurve() {
            CurveFp newCurve = new CurveFp(
                EllipticCurve.Utils.BinaryAscii.numberFromHex("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4"),
                EllipticCurve.Utils.BinaryAscii.numberFromHex("2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be"),
                "brainpoolP256t1",
                new int[] { 1, 3, 36, 3, 3, 2, 8, 1, 1, 8 }
            );

            string privateKeyPem = new PrivateKey(newCurve).toPem();
            string publicKeyPem = new PrivateKey(newCurve).publicKey().toPem();

            var ex1 = Assert.Throws<System.ArgumentException>(() => PrivateKey.fromPem(privateKeyPem));
            Assert.Contains("Unknown curve", ex1.Message);

            var ex2 = Assert.Throws<System.ArgumentException>(() => PublicKey.fromPem(publicKeyPem));
            Assert.Contains("Unknown curve", ex2.Message);
        }
    }
}
