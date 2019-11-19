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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Threading;
using System.Threading.Tasks;

using Org.BouncyCastle.Utilities.Encoders;

namespace GooglePay.PaymentDataCryptography
{
    using KeysDict = IReadOnlyDictionary<string, IEnumerable<string>>;

    /// <summary>
    /// Automatically downloads and parses Google's signing keys used to verify
    /// the ECDSA signature of the signed message.
    /// </summary>
    public class GoogleKeyProvider : ISignatureKeyProvider
    {
        private const string GoogleProductionKeyUrl = "https://payments.developers.google.com/paymentmethodtoken/keys.json";
        private const string GoogleTestKeyUrl = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json";

        private readonly Util.IClock _clock = Util.SystemClock.Default;
        private readonly string _url;
        private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);
        private Task<KeysDict> _googleKeysTask = null;
        private KeysDict _googleKeys = null;
        private DateTime _lastUpdate;
        private TimeSpan _updateTimeSpan = TimeSpan.FromDays(7);

        private readonly string _testData = null;

        public GoogleKeyProvider(bool isTest = false) =>
            _url = isTest ? GoogleTestKeyUrl : GoogleProductionKeyUrl;

        internal GoogleKeyProvider(string testData, Util.IClock mockClock) {
            _testData = testData;
            _clock = mockClock;
        }

        /// <summary>
        /// Returns one or more Google signing keys associated with the given
        /// protocol version.
        /// </summary>
        /// <param name="protocolVersion">Protocol version of the message</param>
        /// <returns>One or more public keys in Base64 ASN.1 byte format</returns>
        public async Task<IEnumerable<string>> GetPublicKeys(string protocolVersion)
        {
            await FetchKeysIfNeeded().ConfigureAwait(false);
            await _semaphoreSlim.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_googleKeys.ContainsKey(protocolVersion))
                {
                    return null;
                }
                return _googleKeys[protocolVersion];
            }
            finally
            {
                _semaphoreSlim.Release();
            }
        }

        /// <summary>
        /// Initiates fetch of new signing keys from Google's servers, if
        /// the currently cached keys need an update.
        /// </summary>
        public Task PrefetchKeys() =>
            FetchKeysIfNeeded();

        private Task FetchKeysIfNeeded(bool force = false)
        {
            _semaphoreSlim.Wait();
            try
            {
                if (!NeedsUpdate())
                {
                    return Task.FromResult(_googleKeys);
                }
                if (_googleKeysTask != null)
                {
                    return _googleKeysTask;
                }
                _googleKeysTask = FetchGoogleKeys();
            }
            finally
            {
                _semaphoreSlim.Release();
            }
            return WaitForKeys();
            async Task WaitForKeys()
            {
                await _semaphoreSlim.WaitAsync().ConfigureAwait(false);
                try
                {
                    KeysDict keys = await _googleKeysTask.ConfigureAwait(false);
                    _googleKeysTask = null;
                    _googleKeys = keys;
                    _lastUpdate = DateTime.UtcNow;
                }
                finally
                {
                    _semaphoreSlim.Release();
                }
            }
        }

        private async Task<KeysDict> FetchGoogleKeys()
        {
            if (_testData != null)
            {
                return FetchGoogleKeysTest();
            }

            using (var client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(_url).ConfigureAwait(false);
                if (response.Headers.CacheControl.MaxAge.HasValue)
                {
                    _updateTimeSpan = response.Headers.CacheControl.MaxAge.Value;
                }
                Stream json = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                var keys = Util.Json.Parse<GoogleKeysObject>(json);
                return ParseGoogleKeys(keys);
            }
        }

        private KeysDict FetchGoogleKeysTest()
        {
            var keys = Util.Json.Parse<GoogleKeysObject>(_testData);
            return ParseGoogleKeys(keys);
        }

        private KeysDict ParseGoogleKeys(GoogleKeysObject keys)
        {
            return keys.Keys
                .Where(key => key.Valid(_clock))
                .GroupBy(key => key.ProtocolVersion)
                .ToDictionary(key => key.Key, key => key.Select(x => x.KeyValue));
        }

        // Must be called inside _lock.
        private bool NeedsUpdate() =>
            _googleKeys == null || DateTime.UtcNow - _lastUpdate >= _updateTimeSpan;

        [DataContract]
        internal class GoogleKeysObject
        {
            [DataMember(Name = "keys")]
            internal GoogleKeyObject[] Keys { get; set; }
        }

        [DataContract]
        internal class GoogleKeyObject
        {
            [DataMember(Name = "keyValue")]
            internal string KeyValue { get; set; }
            [DataMember(Name = "protocolVersion")]
            internal string ProtocolVersion { get; set; }
            [DataMember(Name = "keyExpiration")]
            internal long KeyExpiration { get; set; }

            internal bool Valid(Util.IClock clock) => KeyExpiration == 0 || DateTimeOffset.FromUnixTimeMilliseconds(KeyExpiration) >= clock.UtcNow;
        }

    }

}
