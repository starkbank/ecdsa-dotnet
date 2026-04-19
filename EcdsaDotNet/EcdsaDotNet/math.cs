using System.Numerics;


namespace EllipticCurve {

    public static class EcdsaMath {

        private const int GENERATOR_WINDOW_BITS = 4;

        public static BigInteger modularSquareRoot(BigInteger value, BigInteger prime) {
            // Tonelli-Shanks algorithm for modular square root. Works for all odd primes.

            if (value == 0) {
                return BigInteger.Zero;
            }
            if (prime == 2) {
                return Utils.Integer.modulo(value, 2);
            }

            // Factor out powers of 2: prime - 1 = Q * 2^S
            BigInteger Q = prime - 1;
            int S = 0;
            while (Q % 2 == 0) {
                Q /= 2;
                S += 1;
            }

            if (S == 1) {  // prime = 3 (mod 4)
                return BigInteger.ModPow(value, (prime + 1) / 4, prime);
            }

            // Find a quadratic non-residue z
            BigInteger z = 2;
            while (BigInteger.ModPow(z, (prime - 1) / 2, prime) != prime - 1) {
                z += 1;
            }

            int M = S;
            BigInteger c = BigInteger.ModPow(z, Q, prime);
            BigInteger t = BigInteger.ModPow(value, Q, prime);
            BigInteger R = BigInteger.ModPow(value, (Q + 1) / 2, prime);

            while (true) {
                if (t == 1) {
                    return R;
                }

                // Find the least i such that t^(2^i) = 1 (mod prime)
                int i = 1;
                BigInteger temp = Utils.Integer.modulo(t * t, prime);
                while (temp != 1) {
                    temp = Utils.Integer.modulo(temp * temp, prime);
                    i += 1;
                }

                BigInteger b = BigInteger.ModPow(c, BigInteger.One << (M - i - 1), prime);
                M = i;
                c = Utils.Integer.modulo(b * b, prime);
                t = Utils.Integer.modulo(t * c, prime);
                R = Utils.Integer.modulo(R * b, prime);
            }
        }

        public static Point multiply(Point p, BigInteger n, BigInteger N, BigInteger A, BigInteger P) {
            // Fast way to multiply point and scalar in elliptic curves
            // using Montgomery ladder for constant-time execution.

            return fromJacobian(
                jacobianMultiply(
                    toJacobian(p),
                    n,
                    N,
                    A,
                    P
                ),
                P
            );
        }

        public static Point multiplyGenerator(CurveFp curve, BigInteger n) {
            // Fast scalar multiplication n*G where G is the curve generator,
            // using a precomputed window table (2^w-ary method). Roughly
            // 2-3x faster than variable-base multiplication because doublings
            // stay cheap and additions use pre-stored multiples of G.

            if (n < 0 || n >= curve.N) {
                n = Utils.Integer.modulo(n, curve.N);
            }
            if (n.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero);
            }

            Point[] table = generatorTable(curve);
            int w = GENERATOR_WINDOW_BITS;
            int mask = (1 << w) - 1;
            BigInteger A = curve.A;
            BigInteger P = curve.P;

            // Jacobian infinity representation uses y=0 to trigger the
            // early-return branches in jacobianAdd.
            Point r = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            int startBit = ((curve.NBitLength - 1) / w) * w;
            for (int bit = startBit; bit >= 0; bit -= w) {
                for (int i = 0; i < w; i++) {
                    r = jacobianDouble(r, A, P);
                }
                int window = (int)((n >> bit) & mask);
                if (window != 0) {
                    r = jacobianAdd(r, table[window], A, P);
                }
            }
            return fromJacobian(r, P);
        }

        private static Point[] generatorTable(CurveFp curve) {
            Point[] cached = curve.generatorTable;
            if (cached != null) {
                return cached;
            }
            lock (curve.generatorTableLock) {
                if (curve.generatorTable != null) {
                    return curve.generatorTable;
                }
                int w = GENERATOR_WINDOW_BITS;
                BigInteger A = curve.A;
                BigInteger P = curve.P;
                int size = 1 << w;
                Point[] table = new Point[size];
                table[0] = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
                Point G = new Point(curve.G.x, curve.G.y, BigInteger.One);
                table[1] = G;
                for (int i = 2; i < size; i++) {
                    table[i] = jacobianAdd(table[i - 1], G, A, P);
                }
                curve.generatorTable = table;
                return table;
            }
        }

        public static Point add(Point p, Point q, BigInteger A, BigInteger P) {
            // Fast way to add two points in elliptic curves

            return fromJacobian(
                jacobianAdd(
                    toJacobian(p),
                    toJacobian(q),
                    A,
                    P
                ),
                P
            );
        }

        public static Point multiplyAndAdd(Point p1, BigInteger n1, Point p2, BigInteger n2, BigInteger N, BigInteger A, BigInteger P) {
            // Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
            // Not constant-time -- use only with public scalars (e.g. verification).

            return fromJacobian(
                shamirMultiply(
                    toJacobian(p1), n1,
                    toJacobian(p2), n2,
                    N, A, P
                ),
                P
            );
        }

        public static BigInteger inv(BigInteger x, BigInteger n) {
            // Modular inverse via extended Euclidean algorithm. Roughly 2-3x
            // faster than Fermat's little theorem (ModPow with exponent n-2)
            // for 256-bit operands.

            if (x.IsZero || (x % n).IsZero) {
                return BigInteger.Zero;
            }

            // Invariants: x0 * x ≡ b (mod n), x1 * x ≡ a (mod n).
            // When a reaches 0, b is gcd(x, n); x0 is the coefficient that
            // multiplies x to give gcd, i.e. the modular inverse when gcd=1.
            BigInteger a = Utils.Integer.modulo(x, n);
            BigInteger b = n;
            BigInteger x0 = BigInteger.Zero;
            BigInteger x1 = BigInteger.One;
            while (!a.IsZero) {
                BigInteger q = b / a;
                BigInteger newA = b - q * a;
                BigInteger newX1 = x0 - q * x1;
                b = a;
                a = newA;
                x0 = x1;
                x1 = newX1;
            }
            return Utils.Integer.modulo(x0, n);
        }

        private static Point toJacobian(Point p) {
            // Convert point to Jacobian coordinates
            return new Point(p.x, p.y, BigInteger.One);
        }

        private static Point fromJacobian(Point p, BigInteger P) {
            // Convert point back from Jacobian coordinates
            // Guard: handle point at infinity
            if (p.y.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero);
            }

            BigInteger z = inv(p.z, P);
            BigInteger z2 = Utils.Integer.modulo(z * z, P);
            BigInteger z3 = Utils.Integer.modulo(z2 * z, P);

            return new Point(
                Utils.Integer.modulo(p.x * z2, P),
                Utils.Integer.modulo(p.y * z3, P)
            );
        }

        private static Point jacobianDouble(Point p, BigInteger A, BigInteger P) {
            // Double a point in elliptic curves

            BigInteger py = p.y;
            if (py.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero);
            }

            BigInteger px = p.x;
            BigInteger pz = p.z;
            BigInteger ysq = Utils.Integer.modulo(py * py, P);
            BigInteger S = Utils.Integer.modulo(4 * px * ysq, P);
            BigInteger pz2 = Utils.Integer.modulo(pz * pz, P);
            BigInteger M;
            if (A.IsZero) {
                // secp256k1 shortcut: A == 0 drops the A*pz^4 term.
                M = Utils.Integer.modulo(3 * px * px, P);
            } else if (A == -3 || A == P - 3) {
                // prime256v1 shortcut: A == -3 collapses to 3*(px-pz^2)*(px+pz^2).
                M = Utils.Integer.modulo(3 * (px - pz2) * (px + pz2), P);
            } else {
                M = Utils.Integer.modulo(3 * px * px + A * pz2 * pz2, P);
            }
            BigInteger nx = Utils.Integer.modulo(M * M - 2 * S, P);
            BigInteger ny = Utils.Integer.modulo(M * (S - nx) - 8 * ysq * ysq, P);
            BigInteger nz = Utils.Integer.modulo(2 * py * pz, P);

            return new Point(nx, ny, nz);
        }

        private static Point jacobianAdd(Point p, Point q, BigInteger A, BigInteger P) {
            // Add two points in elliptic curves

            if (p.y.IsZero) {
                return q;
            }
            if (q.y.IsZero) {
                return p;
            }

            BigInteger px = p.x, py = p.y, pz = p.z;
            BigInteger qx = q.x, qy = q.y, qz = q.z;

            BigInteger pz2 = Utils.Integer.modulo(pz * pz, P);
            BigInteger U2 = Utils.Integer.modulo(qx * pz2, P);
            BigInteger S2 = Utils.Integer.modulo(qy * pz2 * pz, P);

            BigInteger U1, S1;
            if (qz.IsOne) {
                // Mixed affine+Jacobian add: qz²=qz³=1 saves four multiplications.
                U1 = px;
                S1 = py;
            } else {
                BigInteger qz2 = Utils.Integer.modulo(qz * qz, P);
                U1 = Utils.Integer.modulo(px * qz2, P);
                S1 = Utils.Integer.modulo(py * qz2 * qz, P);
            }

            if (U1 == U2) {
                if (S1 != S2) {
                    return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
                }
                return jacobianDouble(p, A, P);
            }

            BigInteger H = U2 - U1;
            BigInteger R = S2 - S1;
            BigInteger H2 = Utils.Integer.modulo(H * H, P);
            BigInteger H3 = Utils.Integer.modulo(H * H2, P);
            BigInteger U1H2 = Utils.Integer.modulo(U1 * H2, P);
            BigInteger nx = Utils.Integer.modulo(R * R - H3 - 2 * U1H2, P);
            BigInteger ny = Utils.Integer.modulo(R * (U1H2 - nx) - S1 * H3, P);
            BigInteger nz = qz.IsOne ? Utils.Integer.modulo(H * pz, P) : Utils.Integer.modulo(H * pz * qz, P);

            return new Point(nx, ny, nz);
        }

        private static Point jacobianMultiply(Point p, BigInteger n, BigInteger N, BigInteger A, BigInteger P) {
            // Multiply point and scalar in elliptic curves using Montgomery ladder
            // for constant-time execution.

            if (p.y.IsZero || n.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            }

            if (n < 0 || n >= N) {
                n = Utils.Integer.modulo(n, N);
            }

            if (n.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            }

            // Montgomery ladder: always performs one add and one double per bit
            Point r0 = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            Point r1 = new Point(p.x, p.y, p.z);

            int bitLen = Utils.Integer.bitLength(n);
            for (int i = bitLen - 1; i >= 0; i--) {
                if (((n >> i) & 1).IsZero) {
                    r1 = jacobianAdd(r0, r1, A, P);
                    r0 = jacobianDouble(r0, A, P);
                } else {
                    r0 = jacobianAdd(r0, r1, A, P);
                    r1 = jacobianDouble(r1, A, P);
                }
            }

            return r0;
        }

        private static Point shamirMultiply(Point jp1, BigInteger n1, Point jp2, BigInteger n2, BigInteger N, BigInteger A, BigInteger P) {
            // Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
            // Not constant-time -- use only with public scalars (e.g. verification).

            if (n1 < 0 || n1 >= N) {
                n1 = Utils.Integer.modulo(n1, N);
            }
            if (n2 < 0 || n2 >= N) {
                n2 = Utils.Integer.modulo(n2, N);
            }

            Point jp1p2 = jacobianAdd(jp1, jp2, A, P);

            int l1 = Utils.Integer.bitLength(n1);
            int l2 = Utils.Integer.bitLength(n2);
            int l = l1 > l2 ? l1 : l2;
            Point r = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);

            for (int i = l - 1; i >= 0; i--) {
                r = jacobianDouble(r, A, P);
                int b1 = (int)((n1 >> i) & 1);
                int b2 = (int)((n2 >> i) & 1);
                if (b1 != 0) {
                    r = jacobianAdd(r, b2 != 0 ? jp1p2 : jp1, A, P);
                } else if (b2 != 0) {
                    r = jacobianAdd(r, jp2, A, P);
                }
            }

            return r;
        }

    }

}
