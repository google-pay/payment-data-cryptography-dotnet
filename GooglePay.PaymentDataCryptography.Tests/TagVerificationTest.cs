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

using Org.BouncyCastle.Utilities.Encoders;

using GooglePay.PaymentDataCryptography;

namespace GooglePay.PaymentDataCryptography.Tests
{
    public class TagVerificationTest
    {
        [Fact]
        public void TestVerify()
        {
            byte[] macKey = Hex.Decode("D5F72946AAE92D54697A4FF305B6F9F4");
            TagVerification verification = new TagVerification(macKey);
            byte[] message = Base64.Decode("12jUObueVTdy");
            Assert.True(verification.Verify(message, "ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE="));
        }
    }
}
