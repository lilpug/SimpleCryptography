using System;
using System.Text.Json;
using SimpleCryptography.Business.EncryptionServices;
using SimpleCryptography.Data.Interfaces;
using Xunit;

namespace SimpleCryptography.UnitTests.EncryptionServices
{
    public class BaseEncryptionServiceTests
    {
        //Mocks the abstracted class so we can test it
        private class MockService : BaseEncryptionService
        {
            public override IKeyResult CreateKeyResult()
            {
                throw new System.NotImplementedException();
            }

            protected override byte[] Encrypt(byte[] key, byte[] data)
            {
                return data;
            }

            protected override byte[] Decrypt(byte[] key, byte[] encryptedData)
            {
                return encryptedData;
            }
        }
        
        private string Key { get; set; }

        public BaseEncryptionServiceTests()
        {
            Key = Convert.ToBase64String(new byte[] {123, 123, 123, 123, 123});
        }

        private IEncryptionService CreateInstance()
        {
            return new MockService();
        }
        
        [Fact]
        public void EncryptToStringEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.EncryptToString(Key, null);
            });
            Assert.True(exception.Message.IndexOf("data is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void EncryptToStringEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.EncryptToString(null, "test data");
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void EncryptToStringSuccess()
        {
            const string testData = "test data";
            var data = JsonSerializer.SerializeToUtf8Bytes(testData);
            
            var instance = CreateInstance();
            var result = instance.EncryptToString(Key, testData);
            
            Assert.NotNull(result);
            Assert.Equal(Convert.FromBase64String(result), data);
        }
        
        
        [Fact]
        public void EncryptToBytesEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.EncryptToBytes(Key, null);
            });
            Assert.True(exception.Message.IndexOf("data is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void EncryptToBytesEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.EncryptToBytes(null, "test data");
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void EncryptToBytesSuccess()
        {
            const string testData = "test data";
            var data = JsonSerializer.SerializeToUtf8Bytes(testData);
            
            var instance = CreateInstance();
            var result = instance.EncryptToBytes(Key, testData);
            
            Assert.NotNull(result);
            Assert.Equal(result, data);
        }

        [Fact]
        public void DecryptToTypeByteEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.DecryptToType<string>(Key, (byte[])null);
            });
            Assert.True(exception.Message.IndexOf("encryptedData is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void DecryptToTypeByteEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.DecryptToType<string>(null, new byte[] {123});
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void DecryptToTypeByteSuccess()
        {
            const string testData = "test data";
            var data = JsonSerializer.SerializeToUtf8Bytes(testData);
            
            var instance = CreateInstance();
            var result = instance.DecryptToType<string>(Key, data);
            
            Assert.NotNull(result);
            Assert.Equal(result, testData);
        }
        
        [Fact]
        public void DecryptToTypeStringEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.DecryptToType<string>(Key, (string)null);
            });
            Assert.True(exception.Message.IndexOf("encryptedData is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void DecryptToTypeStringEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.DecryptToType<string>(null, "test");
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void DecryptToTypeStringSuccess()
        {
            const string testData = "test data";
            var data = JsonSerializer.SerializeToUtf8Bytes(testData);
            var convertedData = Convert.ToBase64String(data);
            
            var instance = CreateInstance();
            var result = instance.DecryptToType<string>(Key, convertedData);
            
            Assert.NotNull(result);
            Assert.Equal(result, testData);
        }
    }
}