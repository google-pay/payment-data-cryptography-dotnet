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

using Xunit;

using System.Linq;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

using GooglePay.PaymentDataCryptography;

namespace GooglePay.PaymentDataCryptography.Tests
{
    public class KeyDerivationTest
    {
        [Fact]
        public void TestDerive()
        {
            ECPrivateKeyParameters privateKey = KeyParser.ParsePrivateKeyDer("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm");

            string ephemeralPublicKey = "BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE=";
            var keyDerivation = new KeyDerivation(16, 16);
            KeyDerivation.DerivedKeys keys = keyDerivation.Derive(privateKey, ephemeralPublicKey);

            byte[] expectedSymmetricKey = Hex.Decode("59EDEC98018C6DD4CCAF1119AD247843");
            byte[] expectedMacKey = Hex.Decode("D5F72946AAE92D54697A4FF305B6F9F4");
            Assert.True(keys.SymmetricEncryptionKey.SequenceEqual(expectedSymmetricKey));
            Assert.True(keys.MacKey.SequenceEqual(expectedMacKey));
        }
    }
}
