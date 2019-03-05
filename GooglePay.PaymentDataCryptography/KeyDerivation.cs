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
using System.Linq;
using System.Text;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace GooglePay.PaymentDataCryptography
{
    internal class KeyDerivation
    {
        private const int SharedSecretSize = 32;
        private static readonly byte[] HkdfInfo = Encoding.ASCII.GetBytes("Google");
        private readonly int _symmetricKeySize;
        private readonly int _macKeySize;
        private readonly int _hkdfSize;

        public class DerivedKeys
        {
            public readonly byte[] SymmetricEncryptionKey;
            public readonly byte[] MacKey;

            protected internal DerivedKeys(byte[] hkdf, int symmetricKeySize, int macKeySize)
            {
                SymmetricEncryptionKey = new byte[symmetricKeySize];
                Array.Copy(hkdf, 0, SymmetricEncryptionKey, 0, symmetricKeySize);

                MacKey = new byte[macKeySize];
                Array.Copy(hkdf, symmetricKeySize, MacKey, 0, macKeySize);
            }
        }

        public KeyDerivation(int symmetricKeySize, int macKeySize)
        {
            _symmetricKeySize = symmetricKeySize;
            _macKeySize = macKeySize;
            _hkdfSize = symmetricKeySize + macKeySize;
        }

        public DerivedKeys Derive(ECPrivateKeyParameters privateKey, string ephemeralPublicKey)
        {
            byte[] publicKeyBytes = Base64.Decode(ephemeralPublicKey);
            ECPublicKeyParameters publicKey = KeyParser.ParsePublicKey(publicKeyBytes);

            byte[] sharedSecret = ComputeSharedSecret(privateKey, publicKey);
            byte[] ikm = publicKeyBytes.Concat(sharedSecret).ToArray();

            return new DerivedKeys(ComputeHkdf(ikm), _symmetricKeySize, _macKeySize);
        }

        private byte[] ComputeHkdf(byte[] ikm)
        {
            var generator = new HkdfBytesGenerator(new Sha256Digest());
            var parameters = new HkdfParameters(ikm, null, HkdfInfo);
            generator.Init(parameters);
            byte[] output = new byte[_hkdfSize];
            generator.GenerateBytes(output, 0, _hkdfSize);
            return output;
        }

        internal static byte[] ComputeSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
        {
            if (!KeyParser.ValidateCurve(privateKey))
            {
                throw new ArgumentException("Private key not on NIST P-256 curve", "privateKey");
            }
            if (!KeyParser.ValidateCurve(publicKey))
            {
                throw new ArgumentException("Public key not on NIST P-256 curve", "publicKey");
            }

            var ecdhAgreement = new ECDHBasicAgreement();
            ecdhAgreement.Init(privateKey);
            BigInteger secret = ecdhAgreement.CalculateAgreement(publicKey);
            return BigIntegers.AsUnsignedByteArray(SharedSecretSize, secret);
        }
    }
}
