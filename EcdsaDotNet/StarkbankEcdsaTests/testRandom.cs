using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestRandom {

        [Fact]
        public void testMany() {
            for (int i = 0; i < 100; i++) {
                PrivateKey privateKey1 = new PrivateKey();
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
        }
    }
}
