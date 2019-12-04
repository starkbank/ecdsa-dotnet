using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestPrivateKey {

        [Fact]
        public void testPemConversion() {
            PrivateKey privateKey1 = new PrivateKey();
            string pem = privateKey1.toPem();
            PrivateKey privateKey2 = PrivateKey.fromPem(pem);

            Assert.Equal(privateKey1.secret, privateKey2.secret);
            Assert.Equal(privateKey1.curve, privateKey2.curve);
        }

        [Fact]
        public void testDerConversion() {
            PrivateKey privateKey1 = new PrivateKey();
            byte[] der = privateKey1.toDer();
            PrivateKey privateKey2 = PrivateKey.fromDer(der);

            Assert.Equal(privateKey1.secret, privateKey2.secret);
            Assert.Equal(privateKey1.curve, privateKey2.curve);
        }

        [Fact]
        public void testStringConversion() {
            PrivateKey privateKey1 = new PrivateKey();
            string str = privateKey1.toString();
            PrivateKey privateKey2 = PrivateKey.fromString(str);

            Assert.Equal(privateKey1.secret, privateKey2.secret);
            Assert.Equal(privateKey1.curve, privateKey2.curve);
        }

    }

}
