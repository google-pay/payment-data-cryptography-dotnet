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

using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace GooglePay.PaymentDataCryptography
{
    internal class MessageDecryption
    {
        private static readonly byte[] EmptyIV = new byte[16];
        private readonly BufferedBlockCipher _cipher;

        public MessageDecryption(byte[] symmetricEncryptionKey)
        {
            var key = new KeyParameter(symmetricEncryptionKey);
            _cipher = new BufferedBlockCipher(new SicBlockCipher(new AesEngine()));
            _cipher.Init(false, new ParametersWithIV(key, EmptyIV));
        }

        public string Decrypt(byte[] data)
        {
            _cipher.Reset();
            byte[] bytes = _cipher.DoFinal(data, 0, data.Length);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
