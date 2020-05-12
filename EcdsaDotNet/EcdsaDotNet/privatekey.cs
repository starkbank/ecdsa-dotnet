using System.Collections.Generic;
using System.Numerics;
using System;


namespace EllipticCurve {

    public class PrivateKey {

        public CurveFp curve { get; private set; }
        public BigInteger secret { get; private set; }

        public PrivateKey(string curve="secp256k1", BigInteger? secret=null) {
            this.curve = Curves.getCurveByName(curve);

            if (secret == null) {
                secret = Utils.Integer.randomBetween(1, this.curve.N - 1);
            }
            this.secret = (BigInteger)secret;
        }

        public PublicKey publicKey() {
            Point publicPoint = EcdsaMath.multiply(curve.G, secret, curve.N, curve.A, curve.P);
            return new PublicKey(publicPoint, curve);
        }

        public byte[] toString() {
            return Utils.BinaryAscii.stringFromNumber(secret, curve.length());
        }

        public byte[] toDer() {
            byte[] encodedPublicKey = publicKey().toString(true);

            return Utils.Der.encodeSequence(
                new List<byte[]> {
                    Utils.Der.encodeInteger(1),
                    Utils.Der.encodeOctetString(toString()),
                    Utils.Der.encodeConstructed(0, Utils.Der.encodeOid(curve.oid)),
                    Utils.Der.encodeConstructed(1, encodedPublicKey)
                }
            );
        }

        public string toPem() {
            return Utils.Der.toPem(toDer(), "EC PRIVATE KEY");
        }

        public static PrivateKey fromPem (string str) {
            string[] split = str.Split(new string[] { "-----BEGIN EC PRIVATE KEY-----" }, StringSplitOptions.None);

            if (split.Length != 2) {
                throw new ArgumentException("invalid PEM");
            }

            return fromDer(Utils.Der.fromPem(split[1]));
        }

        public static PrivateKey fromDer (byte[] der) {
            Tuple<byte[], byte[]> removeSequence = Utils.Der.removeSequence(der);
            if (removeSequence.Item2.Length > 0) {
                throw new ArgumentException("trailing junk after DER private key: " + Utils.BinaryAscii.hexFromBinary(removeSequence.Item2));
            }

            Tuple<BigInteger, byte[]> removeInteger = Utils.Der.removeInteger(removeSequence.Item1);
            if (removeInteger.Item1 != 1) {
                throw new ArgumentException("expected '1' at start of DER private key, got " + removeInteger.Item1.ToString());
            }

            Tuple<byte[], byte[]> removeOctetString = Utils.Der.removeOctetString(removeInteger.Item2);
            byte[] privateKeyStr = removeOctetString.Item1;

            Tuple<int, byte[], byte[]> removeConstructed = Utils.Der.removeConstructed(removeOctetString.Item2);
            int tag = removeConstructed.Item1;
            byte[] curveOidString = removeConstructed.Item2;
            if (tag != 0) {
                throw new ArgumentException("expected tag 0 in DER private key, got " + tag.ToString());
            }

            Tuple<int[], byte[]> removeObject = Utils.Der.removeObject(curveOidString);
            int[] oidCurve = removeObject.Item1;
            if (removeObject.Item2.Length > 0) {
                throw new ArgumentException(
                    "trailing junk after DER private key curve_oid: " +
                    Utils.BinaryAscii.hexFromBinary(removeObject.Item2)
                );
            }

            string stringOid = string.Join(",", oidCurve);

            if (!Curves.curvesByOid.ContainsKey(stringOid))
            {
                int numCurves = Curves.supportedCurves.Length;
                string[] supportedCurves = new string[numCurves];
                for (int i = 0; i < numCurves; i++)
                {
                    supportedCurves[i] = Curves.supportedCurves[i].name;
                }
                throw new ArgumentException(
                    "Unknown curve with oid [" +
                    string.Join(", ", oidCurve) +
                    "]. Only the following are available: " +
                    string.Join(", ", supportedCurves)
                );
            }

            CurveFp curve = Curves.curvesByOid[stringOid];

            if (privateKeyStr.Length < curve.length()) {
                int length = curve.length() - privateKeyStr.Length;
                string padding = "";
                for (int i = 0; i < length; i++) {
                    padding += "00";
                }
                    privateKeyStr = Utils.Der.combineByteArrays(new List<byte[]> { Utils.BinaryAscii.binaryFromHex(padding), privateKeyStr });
            }

            return fromString(privateKeyStr, curve.name);

        }

        public static PrivateKey fromString (byte[] str, string curve="secp256k1") {
            return new PrivateKey(curve, Utils.BinaryAscii.numberFromString(str));
        }
    }
}
