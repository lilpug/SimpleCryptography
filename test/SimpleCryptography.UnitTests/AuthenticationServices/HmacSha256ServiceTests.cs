using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using SimpleCryptography.Business.AuthenticationServices;
using Xunit;

namespace SimpleCryptography.UnitTests.AuthenticationServices
{
    public class HmacSha256ServiceTests
    {
        private class MockService : HmacSha256Service
        {
            public int TestGetTagSize()
            {
                return GetTagSize();
            }

            public HMAC TestCreateInstance(byte[] key)
            {
                return CreateInstance(key);
            }
        }

        [Fact]
        public void CreateInstanceCheck()
        {
            var instance = new MockService();
            var result = instance.TestCreateInstance(new byte[] {123,123});
            
            Assert.NotNull(result);
            Assert.True(result is HMACSHA256);
        }

        [Fact]
        public void GetTagSize()
        {
            var instance = new MockService();
            var result = instance.TestGetTagSize();
            
            Assert.NotEqual(default, result);
            Assert.Equal( 256 / 8, result);
        }
    }
}