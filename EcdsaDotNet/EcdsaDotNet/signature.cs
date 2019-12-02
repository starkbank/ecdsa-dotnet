using System.Numerics;
using System;


namespace EllipticCurve {

    public class Signature {

        public BigInteger r { get; }
        public BigInteger s { get; }

        public Signature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        public string toDer() {
            string[] sequence = { Utils.Der.encodeInteger(this.r), Utils.Der.encodeInteger(this.s) };
            return Utils.BinaryAscii.binaryFromHex(Utils.Der.encodeSequence(sequence));
        }

        public string toBase64() {
            return Utils.Base64.encode(toDer());
        }

        public static Signature fromDer(string byteString) {
            Tuple<string, string> removeSequence = Utils.Der.removeSequence(byteString);
            string rs = removeSequence.Item1;
            string removeSequenceTrail = removeSequence.Item2;

            if (removeSequenceTrail.Length > 0) {
                throw new ArgumentException("trailing junk after DER signature: " + Utils.BinaryAscii.hexFromBinary(removeSequenceTrail));
            }

            Tuple<BigInteger, string> removeInteger = Utils.Der.removeInteger(rs);
            BigInteger r = removeInteger.Item1;
            string rest = removeInteger.Item2;

            removeInteger = Utils.Der.removeInteger(rest);
            BigInteger s = removeInteger.Item1;
            string removeIntegerTrail = removeInteger.Item2;

            if (removeIntegerTrail.Length > 0) {
                throw new ArgumentException("trailing junk after DER numbers: " + Utils.BinaryAscii.hexFromBinary(removeIntegerTrail));
            }

            return new Signature(r, s);

        }

        public static Signature fromBase64(string str) {
            return fromDer(Utils.Base64.decode(str));
        }

    }

}
