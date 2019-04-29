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
using Xunit.Sdk;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

using GooglePay.PaymentDataCryptography;

namespace GooglePay.PaymentDataCryptography.Tests
{
    public class WycheproofTest
    {
        private const string TestDataFilePath = "./wycheproof/testvectors/ecdh_secp256r1_test.json";

        [Theory]
        [MemberData(nameof(WycheproofTestData))]
        private void RunTest(int @base, TestGroupTest test)
        {
            switch (test.Result)
            {
                case "valid":
                    RunTestValid(test);
                    break;
                case "invalid":
                    RunTestInvalid(test);
                    break;
                case "acceptable":
                    RunTestAcceptable(test);
                    break;
            }
        }

        private void RunTestValid(TestGroupTest test)
        {
            ECPublicKeyParameters publicKey = KeyParser.ParsePublicKeyDer(Hex.Decode(test.PublicKey));
            ECPrivateKeyParameters privateKey = KeyParser.ParsePrivateKeyHex(test.PrivateKey);
            byte[] expectedSharedSecret = Hex.Decode(test.SharedSecret);
            byte[] sharedSecret = KeyDerivation.ComputeSharedSecret(privateKey, publicKey);
            Assert.True(sharedSecret.SequenceEqual(expectedSharedSecret));
        }

        private void RunTestInvalid(TestGroupTest test)
        {
            ECPrivateKeyParameters privateKey = KeyParser.ParsePrivateKeyHex(test.PrivateKey);
            byte[] publicKeyBytes = Hex.Decode(test.PublicKey);
            Assert.Throws<ArgumentException>(() =>
            {
                ECPublicKeyParameters publicKey = KeyParser.ParsePublicKeyDer(publicKeyBytes);
                byte[] sharedSecret = KeyDerivation.ComputeSharedSecret(privateKey, publicKey);
            });
        }

        private void RunTestAcceptable(TestGroupTest test)
        {
            try
            {
                RunTestValid(test);
            }
            catch (Exception e)
            {
                // Assert that Assert.True was not the cause of exception.
                Assert.IsNotType<TrueException>(e);
            }
        }

        public static IEnumerable<object[]> WycheproofTestData()
        {
            var tests = LoadTests(TestDataFilePath);
            int i = 0;
            foreach (var testGroup in tests.TestGroups)
            {
                foreach (var testGroupTest in testGroup.Tests)
                {
                    yield return new object[] { i++, testGroupTest };
                }
            }
        }

        private static TestFile LoadTests(string path)
        {
            using (FileStream fs = File.OpenRead(path))
            {
                var serializer = new DataContractJsonSerializer(typeof(TestFile));
                return serializer.ReadObject(fs) as TestFile;
            }
        }
    }

    [DataContract]
    internal class TestFile
    {
        [DataMember(Name = "testGroups")]
        internal TestGroup[] TestGroups { get; set; }
    }

    [DataContract]
    internal class TestGroup
    {
        [DataMember(Name = "curve")]
        internal string Curve { get; set; }
        [DataMember(Name = "encoding")]
        internal string Encoding { get; set; }
        [DataMember(Name = "type")]
        internal string Type { get; set; }
        [DataMember(Name = "tests")]
        internal TestGroupTest[] Tests { get; set; }
    }

    [DataContract]
    public class TestGroupTest
    {
        [DataMember(Name = "public")]
        internal string PublicKey { get; set; }
        [DataMember(Name = "private")]
        internal string PrivateKey { get; set; }
        [DataMember(Name = "shared")]
        internal string SharedSecret { get; set; }
        [DataMember(Name = "result")]
        internal string Result { get; set; }
        [DataMember(Name = "comment")]
        internal string Comment { get; set; }
        [DataMember(Name = "flags")]
        internal string[] Flags { get; set; }
    }
}
