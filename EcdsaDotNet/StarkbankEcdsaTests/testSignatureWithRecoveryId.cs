using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestSignatureWithRecoveryId {

        [Fact]
        public void testDerConversion() {
            PrivateKey privateKey = new PrivateKey();
            string message = "This is a text message";

            Signature signature1 = Ecdsa.sign(message, privateKey);

            byte[] der = signature1.toDer(withRecoveryId: true);
            Signature signature2 = Signature.fromDer(der, recoveryByte: true);

            Assert.Equal(signature1.r, signature2.r);
            Assert.Equal(signature1.s, signature2.s);
            Assert.Equal(signature1.recoveryId, signature2.recoveryId);
        }

        [Fact]
        public void testBase64Conversion() {
            PrivateKey privateKey = new PrivateKey();
            string message = "This is a text message";

            Signature signature1 = Ecdsa.sign(message, privateKey);

            string base64 = signature1.toBase64(withRecoveryId: true);
            Signature signature2 = Signature.fromBase64(base64, recoveryByte: true);

            Assert.Equal(signature1.r, signature2.r);
            Assert.Equal(signature1.s, signature2.s);
            Assert.Equal(signature1.recoveryId, signature2.recoveryId);
        }
    }
}
