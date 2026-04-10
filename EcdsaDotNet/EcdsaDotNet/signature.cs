using System.Numerics;
using System;
using System.Collections.Generic;

namespace EllipticCurve {

    public class Signature {

        public BigInteger r { get; }
        public BigInteger s { get; }
        public int? recoveryId { get; }

        public Signature(BigInteger r, BigInteger s, int? recoveryId = null) {
            this.r = r;
            this.s = s;
            this.recoveryId = recoveryId;
        }

        public byte[] toDer(bool withRecoveryId = false) {
            List<byte[]> sequence = new List<byte[]> { Utils.Der.encodeInteger(r), Utils.Der.encodeInteger(s) };
            byte[] encodedSequence = Utils.Der.encodeSequence(sequence);
            if (!withRecoveryId) {
                return encodedSequence;
            }
            return Utils.Integer.concat(new byte[] { (byte)(27 + (recoveryId ?? 0)) }, encodedSequence);
        }

        public string toBase64(bool withRecoveryId = false) {
            return Utils.Base64.encode(toDer(withRecoveryId));
        }

        public static Signature fromDer(byte[] bytes, bool recoveryByte = false) {
            int? recoveryId = null;
            if (recoveryByte) {
                recoveryId = bytes[0] - 27;
                byte[] rest = new byte[bytes.Length - 1];
                Array.Copy(bytes, 1, rest, 0, rest.Length);
                bytes = rest;
            }

            Tuple<byte[], byte[]> removeSequence = Utils.Der.removeSequence(bytes);
            byte[] rs = removeSequence.Item1;
            byte[] removeSequenceTrail = removeSequence.Item2;

            if (removeSequenceTrail.Length > 0) {
                throw new ArgumentException("trailing junk after DER signature: " + Utils.BinaryAscii.hexFromBinary(removeSequenceTrail));
            }

            Tuple<BigInteger, byte[]> removeInteger = Utils.Der.removeInteger(rs);
            BigInteger r = removeInteger.Item1;
            byte[] rest2 = removeInteger.Item2;

            removeInteger = Utils.Der.removeInteger(rest2);
            BigInteger s = removeInteger.Item1;
            byte[] removeIntegerTrail = removeInteger.Item2;

            if (removeIntegerTrail.Length > 0) {
                throw new ArgumentException("trailing junk after DER numbers: " + Utils.BinaryAscii.hexFromBinary(removeIntegerTrail));
            }

            return new Signature(r, s, recoveryId);

        }

        public static Signature fromBase64(string str, bool recoveryByte = false) {
            return fromDer(Utils.Base64.decode(str), recoveryByte);
        }

    }

}
