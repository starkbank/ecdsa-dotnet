using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestEcdsa {

        [Fact]
        public void testVerifyRightMessage() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "This is the right message";
            Signature signature = Ecdsa.sign(message, privateKey);

            Assert.True(Ecdsa.verify(message, signature, publicKey));
        }

        [Fact]
        public void testVerifyWrongMessage() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message1 = "This is the right message";
            string message2 = "This is the wrong message";
            Signature signature = Ecdsa.sign(message1, privateKey);

            Assert.False(Ecdsa.verify(message2, signature, publicKey));
        }

        [Fact]
        public void testZeroSignature() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            string message = "This is the wrong message";

            Assert.False(Ecdsa.verify(message, new Signature(0, 0), publicKey));
        }
    }
}
