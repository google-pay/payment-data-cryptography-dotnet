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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;

namespace GooglePay.PaymentDataCryptography
{
    internal class SignatureVerification
    {
        private readonly Util.IClock _clock = Util.SystemClock.Default;

        public SignatureVerification() {}
        internal SignatureVerification(Util.IClock mockClock) => _clock = mockClock;

        public bool VerifyMessage(Models.PaymentData paymentData, string sender, string recipient, ISignatureKeyProvider keyProvider)
        {
            string protocolVersion = paymentData.ProtocolVersion;
            byte[] signedString = CreateSignedString(sender, recipient, paymentData.ProtocolVersion, paymentData.SignedMessage);
            byte[] signatureBytes = Base64.Decode(paymentData.Signature);

            var keys = keyProvider.GetPublicKeys(protocolVersion).Result;
            if (keys == null)
            {
                throw new SecurityException($"No valid signing keys found for protocol version {paymentData.ProtocolVersion}");
            }
            switch (protocolVersion)
            {
                case "ECv1":
                    return VerifyMessageECv1(keys, signedString, signatureBytes);
                case "ECv2":
                    return VerifyMessageECv2(keys, signedString, signatureBytes, paymentData.IntermediateSigningKey);
                case "ECv2SigningOnly":
                    return VerifyMessageECv2SigningOnly(keys, signedString, signatureBytes, paymentData.IntermediateSigningKey);
                default:
                    throw new SecurityException($"Unsupported protocol version {paymentData.ProtocolVersion}");
            }
        }

        private bool VerifyMessageECv1(IEnumerable<string> keys, byte[] signedString, byte[] signature) =>
            keys.Any(keyData => VerifySignature(KeyParser.ParsePublicKeyDer(keyData), signedString, signature));

        private bool VerifyMessageECv2(IEnumerable<string> keys, byte[] signedString, byte[] signature, Models.SigningKey intermediateSigningKey)
        {
            if (!intermediateSigningKey.Signatures.Any(intermediateSignature =>
            {
                byte[] signatureBytes = Base64.Decode(intermediateSignature);
                byte[] signedSignatureString = CreateSignedString("Google", "ECv2", intermediateSigningKey.SignedKey);
                return keys.Any(key => VerifySignature(KeyParser.ParsePublicKeyDer(key), signedSignatureString, signatureBytes));
            }))
            {
                throw new SecurityException("No valid signing keys found in payload");
            }

            Models.KeyWithExpiration signedKey = Util.Json.Parse<Models.KeyWithExpiration>(intermediateSigningKey.SignedKey);
            if (!signedKey.Valid(_clock))
            {
                throw new SecurityException("Expired signed key found in payload");
            }
            ECPublicKeyParameters signingKey = KeyParser.ParsePublicKeyDer(signedKey.KeyValue);
            return VerifySignature(signingKey, signedString, signature);
        }
        
        private bool VerifyMessageECv2SigningOnly(IEnumerable<string> keys, byte[] signedString, byte[] signature, Models.SigningKey intermediateSigningKey)
        {
            if (!intermediateSigningKey.Signatures.Any(intermediateSignature =>
                {
                    byte[] signatureBytes = Base64.Decode(intermediateSignature);
                    byte[] signedSignatureString = CreateSignedString("GooglePayPasses", "ECv2SigningOnly", intermediateSigningKey.SignedKey);
                    return keys.Any(key => VerifySignature(KeyParser.ParsePublicKeyDer(key), signedSignatureString, signatureBytes));
                }))
            {
                throw new SecurityException("No valid signing keys found in payload");
            }

            Models.KeyWithExpiration signedKey = Util.Json.Parse<Models.KeyWithExpiration>(intermediateSigningKey.SignedKey);
            if (!signedKey.Valid(_clock))
            {
                throw new SecurityException("Expired signed key found in payload");
            }
            ECPublicKeyParameters signingKey = KeyParser.ParsePublicKeyDer(signedKey.KeyValue);
            return VerifySignature(signingKey, signedString, signature);
        }

        private static bool VerifySignature(ECPublicKeyParameters key, byte[] signedString, byte[] signature)
        {
            var dsaSigner = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
            dsaSigner.Init(false, key);
            dsaSigner.BlockUpdate(signedString, 0, signedString.Length);
            return dsaSigner.VerifySignature(signature);
        }

        private static byte[] CreateSignedString(params string[] components)
        {
            using (var stream = new MemoryStream())
            using (var buffer = new BinaryWriter(stream, Encoding.ASCII))
            {
                foreach (string component in components)
                {
                    Char[] chars = component.ToCharArray();
                    buffer.Write((UInt32)(chars.Length));
                    buffer.Write(chars);
                }
                buffer.Flush();
                return stream.ToArray();
            }
        }
    }
}
