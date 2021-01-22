using System.Security.Cryptography;

namespace SimpleCryptography.Business.AuthenticationServices
{
    public class HmacSha256Service : BaseHmacService
    {
        private const int TagSize = 256 / 8;

        protected override int GetTagSize()
        {
            return TagSize;
        }

        protected override HMAC CreateInstance(byte[] key)
        {
            return new HMACSHA256(key);
        }
    }
}