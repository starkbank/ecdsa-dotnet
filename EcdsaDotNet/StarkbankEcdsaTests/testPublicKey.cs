using Xunit;
using EllipticCurve;


namespace StarkbankEcdsaTests {

    public class TestPublicKey {

        [Fact]
        public void testPemConversion() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey1 = privateKey.publicKey();
            string pem = publicKey1.toPem();
            PublicKey publicKey2 = PublicKey.fromPem(pem);

            Assert.Equal(publicKey1.point.x, publicKey2.point.x);
            Assert.Equal(publicKey1.point.y, publicKey2.point.y);
            Assert.Equal(publicKey1.curve, publicKey2.curve);
        }

        [Fact]
        public void testDerConversion() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey1 = privateKey.publicKey();
            byte[] der = publicKey1.toDer();
            PublicKey publicKey2 = PublicKey.fromDer(der);

            Assert.Equal(publicKey1.point.x, publicKey2.point.x);
            Assert.Equal(publicKey1.point.y, publicKey2.point.y);
            Assert.Equal(publicKey1.curve, publicKey2.curve);
        }

        [Fact]
        public void testStringConversion() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey1 = privateKey.publicKey();
            byte[] str = publicKey1.toString();
            PublicKey publicKey2 = PublicKey.fromString(str);

            Assert.Equal(publicKey1.point.x, publicKey2.point.x);
            Assert.Equal(publicKey1.point.y, publicKey2.point.y);
            Assert.Equal(publicKey1.curve, publicKey2.curve);
        }

    }

}
