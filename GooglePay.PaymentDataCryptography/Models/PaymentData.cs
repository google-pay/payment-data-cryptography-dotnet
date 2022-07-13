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

using System.Runtime.Serialization;

namespace GooglePay.PaymentDataCryptography.Models
{

    [DataContract]
    internal class PaymentData
    {
        [DataMember(Name = "protocolVersion")]
        internal string ProtocolVersion { get; set; }
        [DataMember(Name = "signature")]
        internal string Signature { get; set; }
        [DataMember(Name = "signedMessage")]
        internal string SignedMessage { get; set; }
        [DataMember(Name = "intermediateSigningKey")]
        internal SigningKey IntermediateSigningKey { get; set; }
    }
}
