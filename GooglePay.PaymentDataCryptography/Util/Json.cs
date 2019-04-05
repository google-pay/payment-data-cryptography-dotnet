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

using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace GooglePay.PaymentDataCryptography.Util
{
    internal static class Json
    {
        public static T Parse<T>(Stream json) where T : class
        {
            try
            {
                var serializer = new DataContractJsonSerializer(typeof(T));
                T parsed = serializer.ReadObject(json) as T;
                return parsed;
            }
            catch (SerializationException e)
            {
                throw new SecurityException("Cannot parse JSON", e);
            }
        }

        public static T Parse<T>(byte[] json) where T : class
        {
            using (var stream = new MemoryStream(json))
            {
                return Parse<T>(stream);
            }
        }

        public static T Parse<T>(string json) where T : class
        {
            return Parse<T>(Encoding.UTF8.GetBytes(json));
        }
    }
}
