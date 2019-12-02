using System.Numerics;
using System;


namespace EllipticCurve
{
    public class PrivateKey
    {
        public CurveFp curve { get; private set; }
        public BigInteger secret { get; private set; }

        public PrivateKey(string curve="secp256k1", BigInteger? secret=null) {
            curve = curve.ToLower();

            if (curve == "secp256k1") {
                this.curve = Curves.secp256k1;
            } else if (curve == "p256" | curve == "prime256v1") {
                this.curve = Curves.prime256v1;
            } else {
                throw new ArgumentException("unknown curve " + curve);
            }

            if (secret == null) {
                secret = Utils.Integer.randomBetween(1, this.curve.N - 1);
            }
            this.secret = (BigInteger)secret;
        }

        public PublicKey publicKey() {
            Point publicPoint = EcdsaMath.multiply(curve.G, secret, curve.N, curve.A, curve.P);
            return new PublicKey(publicPoint, curve);
        }

        public string toString() {
            return Utils.BinaryAscii.hexFromNumber(secret, curve.length());
        }

        public string toDer() {
            string encodedPublicKey = publicKey().toString(true);

            return Utils.Der.encodeSequence(
                new string[] {
                    Utils.Der.encodeInteger(1),
                    Utils.Der.encodeOctetString(toString()),
                    Utils.Der.encodeConstructed(0, Utils.Der.encodeOid(curve.oid)),
                    Utils.Der.encodeConstructed(1, Utils.Der.encodeBitString(encodedPublicKey))
                }
            );
        }

        public string toPem() {
            return Utils.Der.toPem(toDer(), "EC PRIVATE KEY");
        }

        public static PrivateKey fromPem (string str) {
            string[] split = str.Split("-----BEGIN EC PRIVATE KEY-----");

            if (split.Length != 2) {
                throw new ArgumentException("invalid PEM");
            }

            return fromDer(Utils.Der.fromPem(split[1]));
        }

        public static PrivateKey fromDer (string str) {
            Tuple<string, string> removeSequence = Utils.Der.removeSequence(str);
            if (removeSequence.Item2.Length > 0) {
                throw new ArgumentException("trailing junk after DER private key: " + Utils.BinaryAscii.hexFromBinary(removeSequence.Item2));
            }

            Tuple<BigInteger, string> removeInteger = Utils.Der.removeInteger(removeSequence.Item1);
            if (removeInteger.Item1 != 1) {
                throw new ArgumentException("expected '1' at start of DER private key, got " + removeInteger.Item1.ToString());
            }

            Tuple<string, string> removeOctetString = Utils.Der.removeOctetString(removeInteger.Item2);
            string privateKeyStr = removeOctetString.Item1;

            Tuple<int, string, string> removeConstructed = Utils.Der.removeConstructed(removeOctetString.Item2);
            int tag = removeConstructed.Item1;
            string curveOidString = removeConstructed.Item2;
            if (tag != 0) {
                throw new ArgumentException("expected tag 0 in DER private key, got " + tag.ToString());
            }

            Tuple<int[], string> removeObject = Utils.Der.removeObject(curveOidString);
            int[] oidCurve = removeObject.Item1;
            if (removeObject.Item2.Length > 0) {
                throw new ArgumentException(
                    "trailing junk after DER private key curve_oid: " +
                    Utils.BinaryAscii.hexFromBinary(removeObject.Item2)
                );
            }

            if (!Curves.curvesByOid.ContainsKey(oidCurve))
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

            CurveFp curve = Curves.curvesByOid[oidCurve];

            if (privateKeyStr.Length < curve.length()) {
                int length = curve.length() - privateKeyStr.Length;
                string padding = "";
                for (int i=0; i < length; i++) {
                    padding += "\x00";
                }
                privateKeyStr = padding + privateKeyStr;
            }

            return fromString(privateKeyStr, curve.name);

        }

        public static PrivateKey fromString (string str, string curve="secp256k1") {
            return new PrivateKey(curve, Utils.BinaryAscii.numberFromHex(str));
        }
    }
}
