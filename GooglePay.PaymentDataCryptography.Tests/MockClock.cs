using System;

using GooglePay.PaymentDataCryptography.Util;

namespace GooglePay.PaymentDataCryptography.Tests
{
    internal class MockClock : IClock
    {
        private readonly DateTime _dateTime;
        public MockClock(long timestamp)
        {
            _dateTime = DateTimeOffset.FromUnixTimeMilliseconds(timestamp).DateTime;
        }

        public DateTime UtcNow => _dateTime;
    }
}
