using SimpleCryptography.Business.EncryptionServices;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Data.KeyResults;
using Xunit;

namespace SimpleCryptography.UnitTests.EncryptionServices
{
    public class AesCbcServiceTests
    {
        private IEncryptionService CreateInstance()
        {
            return new AesCbcService();
        }

        [Fact]
        public void CreateKeyResult()
        {
            var instance = CreateInstance();
            IKeyResult keyResult = instance.CreateKeyResult();
            
            Assert.NotNull(keyResult);
            Assert.True(keyResult is AesKeyResult result && !string.IsNullOrWhiteSpace(result.Key));
        }
        
        [Fact]
        public void EncryptAndDecrypt()
        {
            const string testData = "testing example";
            var instance = CreateInstance();

            var keyResult = instance.CreateKeyResult() as AesKeyResult;
            Assert.NotNull(keyResult);
            
            var encryptedData = instance.EncryptToString(keyResult.Key, testData);
            var result = instance.DecryptToType<string>(keyResult.Key, encryptedData);
            
            Assert.NotNull(result);
            Assert.Equal(result, testData);
        }
    }
}