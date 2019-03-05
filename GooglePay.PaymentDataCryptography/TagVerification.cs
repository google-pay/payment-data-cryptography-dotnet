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

using System.Linq;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace GooglePay.PaymentDataCryptography
{
    internal class TagVerification
    {
        private readonly HMac _hmac;

        public TagVerification(byte[] macKey)
        {
            _hmac = new HMac(new Sha256Digest());
            _hmac.Init(new KeyParameter(macKey));
        }

        public bool Verify(byte[] data, string tag)
        {
            byte[] output = new byte[_hmac.GetMacSize()];
            _hmac.Reset();
            _hmac.BlockUpdate(data, 0, data.Length);
            _hmac.DoFinal(output, 0);

            return output.SequenceEqual(Base64.Decode(tag));
        }
    }
}
