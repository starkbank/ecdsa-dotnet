## A lightweight and fast pure C# ECDSA

### Overview

This is a pure C# implementation of the Elliptic Curve Digital Signature Algorithm. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure C#.

### Security

starkbank-ecdsa includes the following security features:

- **RFC 6979 deterministic nonces**: Eliminates the catastrophic risk of nonce reuse that leaks private keys
- **Low-S signature normalization**: Prevents signature malleability (BIP-62)
- **Public key on-curve validation**: Blocks invalid-curve attacks during verification
- **Montgomery ladder scalar multiplication**: Constant-operation point multiplication to mitigate timing side channels
- **Hash truncation**: Correctly handles hash functions larger than the curve order (e.g. SHA-512 with secp256k1)
- **Fermat's little theorem for modular inverse**: More uniform execution time than the extended Euclidean algorithm

### Installation

To install StarkBank's ECDSA-DotNet, run:

```sh
dotnet add package starkbank-ecdsa
```

### Curves

We currently support `secp256k1` and `prime256v1` (P-256), but you can add more curves to the project. You just need to use the `Curves.add()` function.

### Speed

We ran a test on .NET 10.0 on a MAC Pro. The libraries were run 100 times and the averages displayed below were obtained:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank-ecdsa    |     3.4ms     |  3.1ms  |

The library uses Jacobian Coordinates, a Montgomery ladder for constant-time scalar multiplication, and Shamir's trick for fast signature verification.

### Sample Code

How to sign a json message for [Stark Bank]:

```csharp
using EllipticCurve;

// Generate privateKey from PEM string
PrivateKey privateKey = PrivateKey.fromPem("-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK\noUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB\nRmpeRREXj5aog/Mq8RrdYy75W9q/Ig==\n-----END EC PRIVATE KEY-----\n");

// Create message from json
string message = "{\"transfers\":[{\"amount\":100000000}]}";

Signature signature = Ecdsa.sign(message, privateKey);

// Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
Console.WriteLine(signature.toBase64());

// To double check if the message matches the signature, do this:
PublicKey publicKey = privateKey.publicKey();

Console.WriteLine(Ecdsa.verify(message, signature, publicKey));
```

Simple use:

```csharp
using EllipticCurve;

// Generate new Keys
PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();

string message = "My test message";

// Generate Signature
Signature signature = Ecdsa.sign(message, privateKey);

// To verify if the signature is valid
Console.WriteLine(Ecdsa.verify(message, signature, publicKey));
```

How to add more curves:

```csharp
using EllipticCurve;

CurveFp newCurve = new CurveFp(
    EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00"),
    EllipticCurve.Utils.BinaryAscii.numberFromHex("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f"),
    EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03"),
    EllipticCurve.Utils.BinaryAscii.numberFromHex("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1"),
    EllipticCurve.Utils.BinaryAscii.numberFromHex("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff"),
    EllipticCurve.Utils.BinaryAscii.numberFromHex("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb"),
    "frp256v1",
    new int[] { 1, 2, 250, 1, 223, 101, 256, 1 }
);

Curves.add(newCurve);
```

How to generate compressed public key:

```csharp
using EllipticCurve;

PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();
string compressedPublicKey = publicKey.toCompressed();

Console.WriteLine(compressedPublicKey);
```

How to recover a compressed public key:

```csharp
using EllipticCurve;

string compressedPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
PublicKey publicKey = PublicKey.fromCompressed(compressedPublicKey);

Console.WriteLine(publicKey.toPem());
```

### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

To verify, do this:

```csharp
using EllipticCurve;

string publicKeyPem = EllipticCurve.Utils.File.read("publicKey.pem");
byte[] signatureDer = EllipticCurve.Utils.File.readBytes("signatureDer.txt");
string message = EllipticCurve.Utils.File.read("message.txt");

PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
Signature signature = Signature.fromDer(signatureDer);

Console.WriteLine(Ecdsa.verify(message, signature, publicKey));
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use with [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

You can do the same with this library:

```csharp
using EllipticCurve;

byte[] signatureDer = EllipticCurve.Utils.File.readBytes("signatureDer.txt");

Signature signature = Signature.fromDer(signatureDer);

Console.WriteLine(signature.toBase64());
```

[Stark Bank]: https://starkbank.com

### Run unit tests

```sh
dotnet test EcdsaDotNet/StarkbankEcdsaTests/StarkbankEcdsaTests.csproj
```

### Run benchmark

```sh
dotnet run --project Benchmark/Benchmark.csproj -c Release
```
