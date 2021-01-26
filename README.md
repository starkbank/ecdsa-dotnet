## A lightweight and fast ECDSA implementation

### Overview

This is a pure C# implementation of the Elliptic Curve Digital Signature Algorithm. It is compatible with .NET Standard 1.3, 2.0 & 2.1. It is also compatible with OpenSSL. It uses some elegant math such as Jacobian Coordinates to speed up the ECDSA on pure C#.

### Installation

To install StarkBank`s ECDSA-DotNet, get the package on nugget.

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `curve.cs`

### Speed

We ran a test on Node 13.1.0 on a MAC Pro i5 2019. The libraries ran 100 times and showed the average times displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank-ecdsa    |     3.5ms     |  6.5ms  |
| nethereum          |     8.5ms     |  2.5ms  |



### Sample Code

How to sign a json message for [Stark Bank]:

```cs
using System;
using EllipticCurve;


// Generate privateKey from PEM string
PrivateKey privateKey = PrivateKey.fromPem("-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK\noUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB\nRmpeRREXj5aog/Mq8RrdYy75W9q/Ig==\n-----END EC PRIVATE KEY-----\n");

// Create message from json
string message = "{\n    \"transfers\": [\n        {\n            \"amount\": 100000000,\n            \"taxId\": \"594.739.480-42\",\n            \"name\": \"Daenerys Targaryen Stormborn\",\n            \"bankCode\": \"341\",\n            \"branchCode\": \"2201\",\n            \"accountNumber\": \"76543-8\",\n            \"tags\": [\"daenerys\", \"targaryen\", \"transfer-1-external-id\"]\n        }\n    ]\n}";

Signature signature = Ecdsa.sign(message, privateKey);

// Generate Signature in base64. This result can be sent to Stark Bank in header as Digital-Signature parameter
Console.WriteLine(signature.toBase64());

// To double check if message matches the signature
PublicKey publicKey = privateKey.publicKey();

Console.WriteLine(Ecdsa.verify(message, signature, publicKey));
```

Simple use:

```cs
using System;
using EllipticCurve;


// Generate new Keys
PrivateKey privateKey = new PrivateKey();
PublicKey publicKey = privateKey.publicKey();

string message = "My test message";

// Generate Signature
Signature signature = Ecdsa.sign(message, privateKey);

// Verify if signature is valid
Console.WriteLine(Ecdsa.verify(message, signature, publicKey));
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

It's time to verify:

```cs
using System;
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

NOTE: If you want to create a Digital Signature to use in the [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

With this library, you can do it:

```cs
using System;
using EllipticCurve;


byte[] signatureDer = EllipticCurve.Utils.File.readBytes("signatureDer.txt");

Signature signature = Signature.fromDer(signatureDer);

Console.WriteLine(signature.toBase64());
```

[Stark Bank]: https://starkbank.com

### Run all unit tests
Run StarkbankEcdsaTests on XUnit in Visual Studio
