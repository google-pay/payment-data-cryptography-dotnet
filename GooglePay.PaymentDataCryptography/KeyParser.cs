// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace GooglePay.PaymentDataCryptography
{
    internal static class KeyParser
    {
        private const string Algorithm = "EC";
        private const string CurveName = "prime256v1";

        private static readonly ECDomainParameters Domain = DomainParametersFromX9(
                X962NamedCurves.GetByName(CurveName));

        private static ECDomainParameters DomainParametersFromX9(X9ECParameters x9) =>
            new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());

        public static ECPublicKeyParameters ParsePublicKey(string publicKeyBase64) =>
            ParsePublicKey(Base64.Decode(publicKeyBase64));

        public static ECPublicKeyParameters ParsePublicKey(byte[] publicKeyBytes) =>
            new ECPublicKeyParameters(Algorithm, Domain.Curve.DecodePoint(publicKeyBytes), Domain);

        public static ECPublicKeyParameters ParsePublicKeyDer(string publicKeyDerBase64) =>
            ParsePublicKeyDer(Base64.Decode(publicKeyDerBase64));

        public static ECPublicKeyParameters ParsePublicKeyDer(byte[] publicKeyDer)
        {
            if (!ValidatePublicKeyLength(publicKeyDer.Length))
            {
                throw new ArgumentException("Invalid public key length", "publicKeyDer");
            }
            return (ECPublicKeyParameters)PublicKeyFactory.CreateKey(publicKeyDer);
        }

        public static ECPrivateKeyParameters ParsePrivateKeyHex(string hex) =>
            new ECPrivateKeyParameters(new BigInteger(hex, 16), Domain);

        public static ECPrivateKeyParameters ParsePrivateKey(BigInteger d) =>
            new ECPrivateKeyParameters(d, Domain);

        public static ECPrivateKeyParameters ParsePrivateKeyDer(string privateKeyDerBase64) =>
            ParsePrivateKeyDer(Base64.Decode(privateKeyDerBase64));

        public static ECPrivateKeyParameters ParsePrivateKeyDer(byte[] privateKeyDer)
        {
            return (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyDer);
        }

        public static bool ValidateCurve(ECKeyParameters key) =>
            key.Parameters.Equals(Domain);

        private static bool ValidatePublicKeyLength(int length) =>
            length == 59 || length == 91;

    }
}
