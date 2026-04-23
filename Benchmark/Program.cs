using System;
using System.Diagnostics;
using EllipticCurve;

class Program
{
    const int ROUNDS = 100;

    static void Main(string[] args)
    {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey = privateKey.publicKey();
        string message = "This is a benchmark test message";

        // Warmup
        Signature sig = Ecdsa.sign(message, privateKey);
        Ecdsa.verify(message, sig, publicKey);

        // Benchmark sign
        Stopwatch sw = Stopwatch.StartNew();
        for (int i = 0; i < ROUNDS; i++)
        {
            sig = Ecdsa.sign(message, privateKey);
        }
        sw.Stop();
        double signTime = sw.ElapsedMilliseconds / (double)ROUNDS;

        // Benchmark verify
        sw.Restart();
        for (int i = 0; i < ROUNDS; i++)
        {
            Ecdsa.verify(message, sig, publicKey);
        }
        sw.Stop();
        double verifyTime = sw.ElapsedMilliseconds / (double)ROUNDS;

        Console.WriteLine();
        Console.WriteLine($"starkbank-ecdsa benchmark ({ROUNDS} rounds)");
        Console.WriteLine("---------------------------------------");
        Console.WriteLine($"sign:    {signTime:F1}ms");
        Console.WriteLine($"verify:  {verifyTime:F1}ms");
        Console.WriteLine();
    }
}
