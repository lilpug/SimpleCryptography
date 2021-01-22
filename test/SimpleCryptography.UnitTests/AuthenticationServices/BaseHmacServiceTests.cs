using System;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using SimpleCryptography.Business.AuthenticationServices;
using SimpleCryptography.Data.Interfaces;
using Xunit;

namespace SimpleCryptography.UnitTests.AuthenticationServices
{
    public class BaseHmacServiceTests
    {
        //Mocks the abstracted class so we can test it
        private class MockService : BaseHmacService
        {
            protected override int GetTagSize()
            {
                return  512 / 8;
            }

            protected override HMAC CreateInstance(byte[] key)
            {
                return new HMACSHA512(key);
            }

            public byte[] TestCalculateHash(byte[] key, byte[] data)
            {
                return CalculateHash(key, data);
            }
            
            public bool TestVerifyHash(byte[] key, byte[] data, byte[] tag)
            {
                return VerifyHash(key, data, tag);
            }
            
            public byte[] TestCoreVerify(string key, byte[] data, bool expirePeriod)
            {
                return CoreVerifyData(key, data, expirePeriod);
            }
            
            public byte[] TestCoreSignData(string key, byte[] data, TimeSpan? expirePeriod)
            {
                return CoreSignData(key, data, expirePeriod);
            }
        }

        private string Key { get; set; }
        private byte[] Data { get; set; }
        private byte[] SignedData { get; set; }
        private byte[] SignedDataExpire { get; set; }
        
        public BaseHmacServiceTests()
        {
            Key = "random key string";
            Data = new byte[] { 123,123,123,123};
            var instance = CreateInstance();
            SignedData = instance.SignDataToBytes(Key, Data);
            SignedDataExpire = instance.SignDataToBytes(Key, Data, TimeSpan.FromDays(1));
        }
        
        private MockService CreateInstance()
        {
            return new MockService();
        }


        [Fact]
        public void CalculateAndVerifyHash()
        {
            var key = Encoding.Unicode.GetBytes(Key); 
            
            var instance = CreateInstance();
            var tag = instance.TestCalculateHash(key, Data);
            Assert.NotNull(tag);

            var result = instance.TestVerifyHash(key, Data, tag);
            Assert.True(result);
        }
        
        [Fact]
        public void CoreSignDataEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.TestCoreSignData(null, null, null);
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void CoreSignDataEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.TestCoreSignData(Key, null, null);
            });
            Assert.True(exception.Message.IndexOf("data is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void CoreVerifyDataEmptyKey()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.TestCoreVerify(null, null, false);
            });
            Assert.True(exception.Message.IndexOf("key is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void CoreVerifyDataEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                instance.TestCoreVerify(Key, null, false);
            });
            Assert.True(exception.Message.IndexOf("data is required.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void CoreVerifyDataInvalidEmptyData()
        {
            var instance = CreateInstance();
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                instance.TestCoreVerify(Key, new byte[] {123}, false);
            });
            Assert.True(exception.Message.IndexOf("The supplied data is not in a valid hmac format.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void SignAndVerifyFailure()
        {   
            var instance = CreateInstance();
            
            var signedData = instance.TestCoreSignData(Key, Data, null);
            Assert.NotNull(signedData);
            Assert.True(!Data.SequenceEqual(signedData));
            
            //Changes a bit of the data so its should fail
            signedData[0] = byte.MinValue;
            
            var exception = Assert.Throws<AuthenticationException>(() =>
            {
                instance.TestCoreVerify(Key, signedData, false);
            });
            Assert.NotNull(exception);
            Assert.True(exception.Message.IndexOf("The Authentication check does not match the original calculation.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void SignAndVerify()
        {   
            var instance = CreateInstance();
            
            var signedData = instance.TestCoreSignData(Key, Data, null);
            Assert.NotNull(signedData);
            Assert.True(!Data.SequenceEqual(signedData));
            
            var verifiedData = instance.TestCoreVerify(Key, signedData, false);
            Assert.NotNull(verifiedData);
            Assert.True(Data.SequenceEqual(verifiedData));
        }
        
        [Fact]
        public void SignAndVerifyWithExpirePeriodFailure()
        {   
            TimeSpan expire = TimeSpan.FromSeconds(0);
            
            var instance = CreateInstance();
            
            var signedData = instance.TestCoreSignData(Key, Data, expire);
            Assert.NotNull(signedData);
            Assert.True(!Data.SequenceEqual(signedData));
            
            var exception = Assert.Throws<AuthenticationException>(() =>
            {
                var verifiedData = instance.TestCoreVerify(Key, signedData, true);
            });
            Assert.NotNull(exception);
            Assert.True(exception.Message.IndexOf("The Authentication check failed due to the expiration time.", StringComparison.Ordinal) > -1);
        }
        
        [Fact]
        public void SignAndVerifyWithExpirePeriod()
        {   
            TimeSpan expire = TimeSpan.FromDays(1);
            
            var instance = CreateInstance();
            
            var signedData = instance.TestCoreSignData(Key, Data, expire);
            Assert.NotNull(signedData);
            Assert.True(!Data.SequenceEqual(signedData));
            
            var verifiedData = instance.TestCoreVerify(Key, signedData, true);
            Assert.NotNull(verifiedData);
            Assert.True(Data.SequenceEqual(verifiedData));
        }

        
        
        
        
        
        
        
        
        
        
        
        

        [Fact]
        public void SignDataToStringViaByteData()
        {
            var instance = CreateInstance();
            var result = instance.SignDataToString(Key, Data);
            
            Assert.NotNull(result);
            Assert.True(!string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void SignDataToStringViaStringData()
        {
            var data = Convert.ToBase64String(Data);
            
            var instance = CreateInstance();
            var result = instance.SignDataToString(Key, data);
            
            Assert.NotNull(result);
            Assert.True(!string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void SignDataToStringViaByteDataWithExpirePeriod()
        {
            var instance = CreateInstance();
            var result = instance.SignDataToString(Key, Data, new TimeSpan());
            
            Assert.NotNull(result);
            Assert.True(!string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void SignDataToStringViaStringDataWithExpirePeriod()
        {
            var data = Convert.ToBase64String(Data);
            
            var instance = CreateInstance();
            var result = instance.SignDataToString(Key, data, new TimeSpan());
            
            Assert.NotNull(result);
            Assert.True(!string.Equals(data, result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void SignDataToBytesViaByteData()
        {
            var instance = CreateInstance();
            var result = instance.SignDataToBytes(Key, Data);
            
            Assert.NotNull(result);
            Assert.True(!Data.SequenceEqual(result));
        }
        
        [Fact]
        public void SignDataToBytesViaStringData()
        {
            var data = Convert.ToBase64String(Data);
            
            var instance = CreateInstance();
            var result = instance.SignDataToBytes(Key, data);
            
            Assert.NotNull(result);
            Assert.True(!Data.SequenceEqual(result));
        }
        
        [Fact]
        public void SignDataToBytesViaByteDataWithExpirePeriod()
        {
            var instance = CreateInstance();
            var result = instance.SignDataToBytes(Key, Data, new TimeSpan());
            
            Assert.NotNull(result);
            Assert.True(!Data.SequenceEqual(result));
        }
        
        [Fact]
        public void SignDataToBytesViaStringDataWithExpirePeriod()
        {
            var data = Convert.ToBase64String(Data);
            
            var instance = CreateInstance();
            var result = instance.SignDataToBytes(Key, data, new TimeSpan());
            
            Assert.NotNull(result);
            Assert.True(!Data.SequenceEqual(result));
        }
        
        [Fact]
        public void VerifyDataToStringViaByteData()
        {
            var instance = CreateInstance();
            var result = instance.VerifyDataToString(Key, SignedData);
            
            Assert.NotNull(result);
            Assert.True(string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void VerifyDataToStringViaStringData()
        {
            var data = Convert.ToBase64String(SignedData);
            
            var instance = CreateInstance();
            var result = instance.VerifyDataToString(Key, data);
            
            Assert.NotNull(result);
            Assert.True(string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void VerifyDataToStringViaByteDataWithExpirePeriod()
        {
            var instance = CreateInstance();
            var result = instance.VerifyDataToString(Key, SignedDataExpire, true);
            
            Assert.NotNull(result);
            Assert.True(string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }
        
        [Fact]
        public void VerifyDataToStringViaStringDataWithExpirePeriod()
        {
            var data = Convert.ToBase64String(SignedDataExpire);
            
            var instance = CreateInstance();
            var result = instance.VerifyDataToString(Key, data, true);
            
            Assert.NotNull(result);
            Assert.True(string.Equals(Convert.ToBase64String(Data), result, StringComparison.CurrentCultureIgnoreCase));
        }

        [Fact]
        public void VerifyDataToBytesViaByteData()
        {
            var instance = CreateInstance();
            var result = instance.VerifyDataToBytes(Key, SignedData);
            
            Assert.NotNull(result);
            Assert.True(Data.SequenceEqual(result));
        }
        
        [Fact]
        public void VerifyDataToBytesViaStringData()
        {
            var data = Convert.ToBase64String(SignedData);
            
            var instance = CreateInstance();
            var result = instance.VerifyDataToBytes(Key, data);
            
            Assert.NotNull(result);
            Assert.True(Data.SequenceEqual(result));
        }
        
        [Fact]
        public void VerifyDataToBytesViaByteDataWithExpirePeriod()
        {
            var instance = CreateInstance();
            var result = instance.VerifyDataToBytes(Key, SignedDataExpire, true);
            
            Assert.NotNull(result);
            Assert.True(Data.SequenceEqual(result));
        }
        
        [Fact]
        public void VerifyDataToBytesViaStringDataWithExpirePeriod()
        {
            var data = Convert.ToBase64String(SignedDataExpire);
            
            var instance = CreateInstance();
            var result = instance.VerifyDataToBytes(Key, data, true);
            
            Assert.NotNull(result);
            Assert.True(Data.SequenceEqual(result));
        }
    }
}