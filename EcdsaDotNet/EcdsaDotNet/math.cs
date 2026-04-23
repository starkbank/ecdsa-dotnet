using System.Numerics;


namespace EllipticCurve {

    public static class EcdsaMath {

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
            // Fast scalar multiplication n*G using a precomputed affine table
            // of powers-of-two multiples of G and the width-2 NAF of n. Every
            // non-zero NAF digit triggers one mixed add and zero doublings,
            // trading the ~256 doublings of a windowed method for ~86 adds on
            // average -- a large net reduction in field multiplications for
            // 256-bit scalars.

            if (n < 0 || n >= curve.N) {
                n = Utils.Integer.modulo(n, curve.N);
            }
            if (n.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero);
            }

            Point[] table = generatorPowersTable(curve);
            BigInteger A = curve.A;
            BigInteger P = curve.P;

            Point r = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            int i = 0;
            BigInteger k = n;
            while (k > 0) {
                if (!(k & BigInteger.One).IsZero) {
                    // width-2 NAF digit: -1 or +1
                    int digit = 2 - (int)(k & 3);
                    k -= digit;
                    Point g = table[i];
                    if (digit == 1) {
                        r = jacobianAdd(r, g, A, P);
                    } else {
                        r = jacobianAdd(r, new Point(g.x, P - g.y, BigInteger.One), A, P);
                    }
                }
                k >>= 1;
                i += 1;
            }
            return fromJacobian(r, P);
        }

        private static Point[] generatorPowersTable(CurveFp curve) {
            // Build [G, 2G, 4G, ..., 2^NBitLength * G] in affine (z=1) form,
            // so each add in multiplyGenerator hits the mixed-add fast path.
            Point[] cached = curve.generatorPowersTable;
            if (cached != null) {
                return cached;
            }
            lock (curve.generatorPowersTableLock) {
                if (curve.generatorPowersTable != null) {
                    return curve.generatorPowersTable;
                }
                BigInteger A = curve.A;
                BigInteger P = curve.P;
                Point current = new Point(curve.G.x, curve.G.y, BigInteger.One);
                // NAF of an NBitLength-bit scalar can be up to NBitLength+1 digits.
                Point[] table = new Point[curve.NBitLength + 1];
                table[0] = current;
                for (int i = 1; i <= curve.NBitLength; i++) {
                    Point doubled = jacobianDouble(current, A, P);
                    if (doubled.y.IsZero) {
                        current = doubled;
                    } else {
                        BigInteger zInv = inv(doubled.z, P);
                        BigInteger zInv2 = Utils.Integer.modulo(zInv * zInv, P);
                        BigInteger zInv3 = Utils.Integer.modulo(zInv2 * zInv, P);
                        current = new Point(
                            Utils.Integer.modulo(doubled.x * zInv2, P),
                            Utils.Integer.modulo(doubled.y * zInv3, P),
                            BigInteger.One
                        );
                    }
                    table[i] = current;
                }
                curve.generatorPowersTable = table;
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

        public static Point multiplyAndAdd(Point p1, BigInteger n1, Point p2, BigInteger n2, CurveFp curve) {
            // Compute n1*p1 + n2*p2. If the curve exposes glvParams (e.g.
            // secp256k1), uses the GLV endomorphism to split both scalars into
            // ~128-bit halves and run a 4-scalar simultaneous multi-exponentiation.
            // Otherwise falls back to Shamir's trick with JSF. Not constant-time --
            // use only with public scalars (e.g. verification).

            if (curve.glvParams != null) {
                return glvMultiplyAndAdd(p1, n1, p2, n2, curve);
            }
            return fromJacobian(
                shamirMultiply(
                    toJacobian(p1), n1,
                    toJacobian(p2), n2,
                    curve.N, curve.A, curve.P
                ),
                curve.P
            );
        }

        private static Point glvMultiplyAndAdd(Point p1, BigInteger n1, Point p2, BigInteger n2, CurveFp curve) {
            // Compute n1*p1 + n2*p2 using the GLV endomorphism. Splits each
            // 256-bit scalar into two ~128-bit scalars via k = k1 + k2*lambda
            // (mod N), then runs a 4-scalar simultaneous double-and-add over
            // (p1, phi(p1), p2, phi(p2)) with a 16-entry precomputed table of
            // subset sums. Halves the loop length versus the plain Shamir path.
            GLVParams glv = curve.glvParams;
            BigInteger N = curve.N;
            BigInteger A = curve.A;
            BigInteger P = curve.P;
            BigInteger beta = glv.beta;

            BigInteger[] k1k2 = glvDecompose(Utils.Integer.modulo(n1, N), glv, N);
            BigInteger[] k3k4 = glvDecompose(Utils.Integer.modulo(n2, N), glv, N);

            // Base points (affine, z=1) -- phi((x,y)) = (beta*x mod P, y).
            Point[] bases = new Point[] {
                new Point(p1.x, p1.y, BigInteger.One),
                new Point(Utils.Integer.modulo(beta * p1.x, P), p1.y, BigInteger.One),
                new Point(p2.x, p2.y, BigInteger.One),
                new Point(Utils.Integer.modulo(beta * p2.x, P), p2.y, BigInteger.One),
            };
            BigInteger[] scalars = new BigInteger[] { k1k2[0], k1k2[1], k3k4[0], k3k4[1] };
            for (int i = 0; i < 4; i++) {
                if (scalars[i].Sign < 0) {
                    scalars[i] = -scalars[i];
                    bases[i] = new Point(bases[i].x, P - bases[i].y, BigInteger.One);
                }
            }

            // Precompute table[idx] = sum of bases[i] selected by bits of idx.
            Point[] table = new Point[16];
            Point infinity = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            table[0] = infinity;
            for (int idx = 1; idx < 16; idx++) {
                int low = idx & -idx;
                int i = 0;
                int tmp = low;
                while ((tmp & 1) == 0) { tmp >>= 1; i++; }
                table[idx] = jacobianAdd(table[idx ^ low], bases[i], A, P);
            }

            int maxLen = 0;
            for (int i = 0; i < 4; i++) {
                int bl = Utils.Integer.bitLength(scalars[i]);
                if (bl > maxLen) maxLen = bl;
            }

            Point r = infinity;
            BigInteger s0 = scalars[0], s1 = scalars[1], s2 = scalars[2], s3 = scalars[3];
            for (int bit = maxLen - 1; bit >= 0; bit--) {
                r = jacobianDouble(r, A, P);
                int idx = (int)((s0 >> bit) & 1)
                        | ((int)((s1 >> bit) & 1) << 1)
                        | ((int)((s2 >> bit) & 1) << 2)
                        | ((int)((s3 >> bit) & 1) << 3);
                if (idx != 0) {
                    r = jacobianAdd(r, table[idx], A, P);
                }
            }
            return fromJacobian(r, P);
        }

        private static BigInteger[] glvDecompose(BigInteger k, GLVParams glv, BigInteger N) {
            // Decompose k into (k1, k2) with k = k1 + k2*lambda (mod N) and
            // |k1|, |k2| ~ sqrt(N). Babai rounding against the precomputed
            // basis {(a1, b1), (a2, b2)}; k1 and k2 may be negative.
            BigInteger a1 = glv.a1, b1 = glv.b1, a2 = glv.a2, b2 = glv.b2;
            BigInteger halfN = N / 2;
            BigInteger c1 = (b2 * k + halfN) / N;
            BigInteger c2 = (-b1 * k + halfN) / N;
            BigInteger k1 = k - c1 * a1 - c2 * a2;
            BigInteger k2 = -c1 * b1 - c2 * b2;
            return new BigInteger[] { k1, k2 };
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
            // Compute n1*p1 + n2*p2 using Shamir's trick with Joint Sparse Form
            // (Solinas 2001). JSF picks signed digits in {-1, 0, 1} so at most
            // ~l/2 digit pairs are non-zero, versus ~3l/4 for raw binary. Not
            // constant-time -- use only with public scalars (e.g. verification).

            if (n1 < 0 || n1 >= N) {
                n1 = Utils.Integer.modulo(n1, N);
            }
            if (n2 < 0 || n2 >= N) {
                n2 = Utils.Integer.modulo(n2, N);
            }

            if (n1.IsZero && n2.IsZero) {
                return new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            }

            Point jp1p2 = jacobianAdd(jp1, jp2, A, P);
            Point negJp2 = neg(jp2, P);
            Point jp1mp2 = jacobianAdd(jp1, negJp2, A, P);

            // addTable indexed by (u0+1)*3 + (u1+1) where u0, u1 in {-1, 0, 1}.
            // Index 4 (u0=0, u1=0) is unused (no add for all-zero digit).
            Point[] addTable = new Point[9];
            addTable[(1 + 1) * 3 + (0 + 1)] = jp1;             // (1, 0)
            addTable[(-1 + 1) * 3 + (0 + 1)] = neg(jp1, P);    // (-1, 0)
            addTable[(0 + 1) * 3 + (1 + 1)] = jp2;             // (0, 1)
            addTable[(0 + 1) * 3 + (-1 + 1)] = negJp2;         // (0, -1)
            addTable[(1 + 1) * 3 + (1 + 1)] = jp1p2;           // (1, 1)
            addTable[(-1 + 1) * 3 + (-1 + 1)] = neg(jp1p2, P); // (-1, -1)
            addTable[(1 + 1) * 3 + (-1 + 1)] = jp1mp2;         // (1, -1)
            addTable[(-1 + 1) * 3 + (1 + 1)] = neg(jp1mp2, P); // (-1, 1)

            int[][] digits = jsfDigits(n1, n2);
            Point r = new Point(BigInteger.Zero, BigInteger.Zero, BigInteger.One);
            for (int k = 0; k < digits.Length; k++) {
                r = jacobianDouble(r, A, P);
                int u0 = digits[k][0];
                int u1 = digits[k][1];
                if (u0 != 0 || u1 != 0) {
                    r = jacobianAdd(r, addTable[(u0 + 1) * 3 + (u1 + 1)], A, P);
                }
            }

            return r;
        }

        private static Point neg(Point p, BigInteger P) {
            return new Point(p.x, p.y.IsZero ? BigInteger.Zero : P - p.y, p.z);
        }

        private static int[][] jsfDigits(BigInteger k0, BigInteger k1) {
            // Joint Sparse Form of (k0, k1): list of signed-digit pairs
            // (u0, u1) in {-1, 0, 1}, ordered MSB-first. At most one of any
            // two consecutive pairs is non-zero, giving density ~1/2 instead
            // of ~3/4 from raw binary.
            System.Collections.Generic.List<int[]> digits = new System.Collections.Generic.List<int[]>();
            int d0 = 0;
            int d1 = 0;
            while (!(k0 + d0).IsZero || !(k1 + d1).IsZero) {
                int a0 = (int)((k0 + d0) & 7);
                int a1 = (int)((k1 + d1) & 7);
                int u0;
                if ((a0 & 1) != 0) {
                    u0 = ((a0 & 3) == 1) ? 1 : -1;
                    if ((a0 == 3 || a0 == 5) && (a1 & 3) == 2) {
                        u0 = -u0;
                    }
                } else {
                    u0 = 0;
                }
                int u1;
                if ((a1 & 1) != 0) {
                    u1 = ((a1 & 3) == 1) ? 1 : -1;
                    if ((a1 == 3 || a1 == 5) && (a0 & 3) == 2) {
                        u1 = -u1;
                    }
                } else {
                    u1 = 0;
                }
                digits.Add(new int[] { u0, u1 });
                if (2 * d0 == 1 + u0) {
                    d0 = 1 - d0;
                }
                if (2 * d1 == 1 + u1) {
                    d1 = 1 - d1;
                }
                k0 >>= 1;
                k1 >>= 1;
            }
            digits.Reverse();
            return digits.ToArray();
        }

    }

}
