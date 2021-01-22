using System.Security.Cryptography;

namespace SimpleCryptography.Business.AuthenticationServices
{
    public class HmacSha512Service : BaseHmacService
    {
        private const int TagSize = 512 / 8;

        protected override int GetTagSize()
        {
            return TagSize;
        }

        protected override HMAC CreateInstance(byte[] key)
        {
            return new HMACSHA512(key);
        }
    }
}