using Xunit;
using EllipticCurve;

namespace StarkbankEcdsaTests {

    public class TestCompPubKey {

        [Fact]
        public void testBatch() {
            for (int i = 0; i < 100; i++) {
                PrivateKey privateKey = new PrivateKey();
                PublicKey publicKey = privateKey.publicKey();
                string publicKeyString = publicKey.toCompressed();

                PublicKey recoveredPublicKey = PublicKey.fromCompressed(publicKeyString, publicKey.curve);

                Assert.Equal(publicKey.point.x, recoveredPublicKey.point.x);
                Assert.Equal(publicKey.point.y, recoveredPublicKey.point.y);
            }
        }

        [Fact]
        public void testFromCompressedEven() {
            string publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
            PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
            Assert.Equal(publicKey.toPem(), "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----");
        }

        [Fact]
        public void testFromCompressedOdd() {
            string publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50";
            PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
            Assert.Equal(publicKey.toPem(), "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----");
        }

        [Fact]
        public void testToCompressedEven() {
            PublicKey publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----");
            string publicKeyCompressed = publicKey.toCompressed();
            Assert.Equal(publicKeyCompressed, "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2");
        }

        [Fact]
        public void testToCompressedOdd() {
            PublicKey publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----");
            string publicKeyCompressed = publicKey.toCompressed();
            Assert.Equal(publicKeyCompressed, "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50");
        }
    }
}
