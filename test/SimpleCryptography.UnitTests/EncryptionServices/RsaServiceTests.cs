using SimpleCryptography.Business.EncryptionServices;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Data.KeyResults;
using Xunit;

namespace SimpleCryptography.UnitTests.EncryptionServices
{
    public class RsaServiceTests
    {
        private IEncryptionService CreateInstance()
        {
            return new RsaService();
        }

        [Fact]
        public void CreateKeyResult()
        {
            var instance = CreateInstance();
            IKeyResult keyResult = instance.CreateKeyResult();
            
            Assert.NotNull(keyResult);
            Assert.True(keyResult is RsaKeyResult result && !string.IsNullOrWhiteSpace(result.PrivateKey) && !string.IsNullOrWhiteSpace(result.PublicKey));
        }
        
        [Fact]
        public void EncryptAndDecrypt()
        {
            const string testData = "testing example";
            var instance = CreateInstance();

            var keyResult = instance.CreateKeyResult() as RsaKeyResult;
            Assert.NotNull(keyResult);
            
            var encryptedData = instance.EncryptToString(keyResult.PublicKey, testData);
            var result = instance.DecryptToType<string>(keyResult.PrivateKey, encryptedData);
            
            Assert.NotNull(result);
            Assert.Equal(result, testData);
        }
    }
}