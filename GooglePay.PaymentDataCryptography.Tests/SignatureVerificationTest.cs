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

using GooglePay.PaymentDataCryptography;
using GooglePay.PaymentDataCryptography.Models;

namespace GooglePay.PaymentDataCryptography.Tests
{
    public class SignatureVerificationTest
    {
        private const long _mockTimestamp = 1542233393000;
        private readonly Util.IClock _clock = new MockClock(_mockTimestamp);

        [Fact]
        public void TestVerifyMessage()
        {
            var keyData = "{\"keys\":[{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynwHcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\"protocolVersion\":\"ECv1\"}]}";
            var keyProvider = new GoogleKeyProvider(keyData, _clock);

            var payload = new PaymentData()
            {
                ProtocolVersion = "ECv1",
                Signature = "MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA==",
                SignedMessage = "{\"tag\":\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\u003d\",\"ephemeralPublicKey\":\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\u003d\",\"encryptedMessage\":\"12jUObueVTdy\"}"
            };
            var signatureVerification = new SignatureVerification(_clock);
            Assert.True(signatureVerification.VerifyMessage(payload, "Google", "someRecipient", keyProvider));
        }

        [Fact]
        public void TestVerifyMessageECv2()
        {
            var keyData = "{\"keys\":[{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvhuz8WZo0DhP7Lg1AQtpQpm2i7Gr6yBa+i6mVOwz3iepodYVDE9YGLzUwoL8AEsPUz/26Pg3lofL2u04/edeXg==\",\"protocolVersion\":\"ECv2\",\"keyExpiration\":\"2154841200000\"}]}";
            var keyProvider = new GoogleKeyProvider(keyData, _clock);

            var payload = new PaymentData()
            {
                ProtocolVersion = "ECv2",
                Signature = "MEQCIH6Q4OwQ0jAceFEkGF0JID6sJNXxOEi4r+mA7biRxqBQAiAondqoUpU/bdsrAOpZIsrHQS9nwiiNwOrr24RyPeHA0Q==",
                SignedMessage = "{\"tag\":\"jpGz1F1Bcoi/fCNxI9n7Qrsw7i7KHrGtTf3NrRclt+U\\u003d\",\"ephemeralPublicKey\":\"BJatyFvFPPD21l8/uLP46Ta1hsKHndf8Z+tAgk+DEPQgYTkhHy19cF3h/bXs0tWTmZtnNm+vlVrKbRU9K8+7cZs\\u003d\",\"encryptedMessage\":\"mKOoXwi8OavZ\"}",
                IntermediateSigningKey = new SigningKey()
                {
                    SignedKey = "{\"keyExpiration\":\"1542323393147\",\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw\\u003d\\u003d\"}",
                    Signatures = new string[] { "MEYCIQCO2EIi48s8VTH+ilMEpoXLFfkxAwHjfPSCVED/QDSHmQIhALLJmrUlNAY8hDQRV/y1iKZGsWpeNmIP+z+tCQHQxP0v" }
                }
            };
            var signatureVerification = new SignatureVerification(_clock);
            Assert.True(signatureVerification.VerifyMessage(payload, "Google", "merchant:12345", keyProvider));
        }
    }
}
