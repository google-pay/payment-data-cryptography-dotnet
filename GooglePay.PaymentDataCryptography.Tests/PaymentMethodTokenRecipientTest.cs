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

namespace GooglePay.PaymentDataCryptography.Tests
{
    public class PaymentMethodTokenRecipientTest
    {
        private const long _mockTimestamp = 1542319793000;
        private readonly Util.IClock _clock = new MockClock(_mockTimestamp);

        [Fact]
        public void Test()
        {
            var keyData = "{\"keys\":[{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPYnHwS8uegWAewQtlxizmLFynwHcxRT1PK07cDA6/C4sXrVI1SzZCUx8U8S0LjMrT6ird/VW7be3Mz6t/srtRQ==\",\"protocolVersion\":\"ECv1\"}]}";
            var keyProvider = new GoogleKeyProvider(keyData, _clock);

            string json = "{\"protocolVersion\":\"ECv1\",\"signedMessage\":\"{\\\"tag\\\":\\\"ZVwlJt7dU8Plk0+r8rPF8DmPTvDiOA1UAoNjDV+SqDE\\\\u003d\\\",\\\"ephemeralPublicKey\\\":\\\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE\\\\u003d\\\",\\\"encryptedMessage\\\":\\\"12jUObueVTdy\\\"}\",\"signature\":\"MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA\\u003d\\u003d\"}";
            PaymentMethodTokenRecipient parser = new PaymentMethodTokenRecipient("someRecipient", keyProvider, _clock);
            parser.AddPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm");
            parser.AddPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVmXrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyNXoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz");
            string expected = "plaintext";
            Assert.Equal(expected, parser.Unseal(json));
        }

        [Fact]
        public void TestECv2()
        {
            var keyData = "{\"keys\":[{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvhuz8WZo0DhP7Lg1AQtpQpm2i7Gr6yBa+i6mVOwz3iepodYVDE9YGLzUwoL8AEsPUz/26Pg3lofL2u04/edeXg==\",\"protocolVersion\":\"ECv2\",\"keyExpiration\":\"2154841200000\"}]}";
            var keyProvider = new GoogleKeyProvider(keyData, _clock);

            string json = "{\"protocolVersion\":\"ECv2\",\"signature\":\"MEUCIG39tbaQPwJe28U+UMsJmxUBUWSkwlOv9Ibohacer+CoAiEA8Wuq3lLUCwLQ06D2kErxaMg3b/oLDFbd2gcFze1zDqU=\",\"intermediateSigningKey\":{\"signedKey\":\"{\\\"keyExpiration\\\":\\\"1542394027316\\\",\\\"keyValue\\\":\\\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw\\\\u003d\\\\u003d\\\"}\",\"signatures\":[\"MEYCIQDcXCoB4fYJF3EolxrE2zB+7THZCfKA7cWxSztKceXTCgIhAN/d5eBgx/1A6qKBdH0IS7/aQ7dO4MuEt26OrLCUxZnl\"]},\"signedMessage\":\"{\\\"tag\\\":\\\"TjkIKzIOvCrFvjf7/aeeL8/FZJ3tigaNnerag68hIaw\\\\u003d\\\",\\\"ephemeralPublicKey\\\":\\\"BLJoTmxP2z7M2N6JmaN786aJcT/L/OJfuJKQdIXcceuBBZ00sf5nm2+snxAJxeJ4HYFTdNH4MOJrH58GNDJ9lJw\\\\u003d\\\",\\\"encryptedMessage\\\":\\\"mleAf23XkKjj\\\"}\"}";
            PaymentMethodTokenRecipient parser = new PaymentMethodTokenRecipient("gateway:ariane", keyProvider, _clock);
            parser.AddPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm");
            parser.AddPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVmXrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyNXoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz");
            string expected = "plaintext";
            Assert.Equal(expected, parser.Unseal(json));
        }
    }
}
