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

using System.Collections.Generic;
using System.Threading.Tasks;

namespace GooglePay.PaymentDataCryptography
{
    /// <summary>
    /// Provides the public keys used to verify the ECDSA signature of the message.
    /// </summary>
    public interface ISignatureKeyProvider
    {
        /// <summary>
        /// Returns one or more signing keys associated with the given protocol
        /// version.
        /// </summary>
        /// <param name="protocolVersion">Protocol version of the message</param>
        /// <returns>One or more public keys in Base64 ASN.1 byte format</returns>
        Task<IEnumerable<string>> GetPublicKeys(string protocolVersion);
    }
}
