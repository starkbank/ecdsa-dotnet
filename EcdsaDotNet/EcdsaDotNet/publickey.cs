using System;


namespace EllipticCurve {

    public class PublicKey {

        public Point point { get; }

        public CurveFp curve { get; private set; }

        public PublicKey(Point point, CurveFp curve) {
            this.point = point;
            this.curve = curve;
        }

        public string toString(bool encoded=false) {
            string xString = Utils.BinaryAscii.hexFromNumber(point.x, curve.length());
            string yString = Utils.BinaryAscii.hexFromNumber(point.y, curve.length());

            if (encoded) {
                return xString + yString;
            }
            return "\x00\x04" + xString + yString;
        }

        public string toDer() {
            int[] oidEcPublicKey = { 1, 2, 840, 10045, 2, 1 };
            string encodedEcAndOid = Utils.Der.encodeSequence(
                new string[] {
                    Utils.Der.encodeOid(oidEcPublicKey),
                    Utils.Der.encodeOid(curve.oid)
                }
            );

            return Utils.Der.encodeSequence(
                new string[] {
                    encodedEcAndOid,
                    Utils.Der.encodeBitString(toString(true))
                }
            );
        }

        public string toPem() {
            return Utils.Der.toPem(toDer(), "PUBLIC KEY");
        }

        public static PublicKey fromPem(string str) {
            return fromDer(Utils.Der.fromPem(str));
        }

        public static PublicKey fromDer(string str) {
            Tuple<string, string> removeSequence1 = Utils.Der.removeSequence(str);
            string s1 = removeSequence1.Item1;

            if (removeSequence1.Item2.Length > 0) {
                throw new ArgumentException(
                    "trailing junk after DER public key: " +
                    Utils.BinaryAscii.hexFromBinary(removeSequence1.Item2)
                );
            }

            Tuple<string, string> removeSequence2 = Utils.Der.removeSequence(s1);
            string s2 = removeSequence2.Item1;
            string pointBitString = removeSequence2.Item2;

            Tuple<int[], string> removeObject1 = Utils.Der.removeObject(s2);
            string rest = removeObject1.Item2;

            Tuple<int[], string> removeObject2 = Utils.Der.removeObject(rest);
            int[] oidCurve = removeObject2.Item1;

            if (removeObject2.Item2.Length > 0) {
                throw new ArgumentException(
                    "trailing junk after DER public key objects: " +
                    Utils.BinaryAscii.hexFromBinary(removeObject2.Item2)
                );
            }

            if (!Curves.curvesByOid.ContainsKey(oidCurve)) {
                int numCurves = Curves.supportedCurves.Length;
                string[] supportedCurves = new string[numCurves];
                for (int i=0; i < numCurves; i++) {
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

            Tuple<string, string> removeBitString = Utils.Der.removeBitString(pointBitString);
            string pointString = removeBitString.Item1;

            if (removeBitString.Item2.Length > 0) {
                throw new ArgumentException("trailing junk after public key point-string");
            }

            return fromString(pointString.Substring(2), curve);

        }

        public static PublicKey fromString(string str, CurveFp curve, bool validatePoint=true) {
            int baseLen = curve.length();

            string xs = str.Substring(0, baseLen);
            string ys = str.Substring(baseLen);

            Point p = new Point(
                Utils.BinaryAscii.numberFromHex(xs),
                Utils.BinaryAscii.numberFromHex(ys)
            );

            if (validatePoint & !curve.contains(p)) {
                throw new ArgumentException(
                    "point (" +
                    p.x.ToString() +
                    ", " +
                    p.y.ToString() +
                    ") is not valid for curve " +
                    curve.name
                );
            }

            return new PublicKey(p, curve);

        }

    }

}
