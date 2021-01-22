using System;
using System.Text;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Business.CompressionServices;
using Xunit;

namespace SimpleCryptography.UnitTests.CompressionServices
{
    public class GzipCompressionServiceTests
    {
        private IGzipCompressionService CreateInstance()
        {
            return new GzipCompressionService();
        }
 
        [Fact]
        public void CompressAndDecompress()
        {
            const string testData = "testing example";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            var instance = CreateInstance();

            var compressedData = instance.Compress(data);
            Assert.NotNull(compressedData);
            Assert.NotEqual(data, compressedData);

            var uncompressedData = instance.Decompress(compressedData);
            Assert.NotNull(uncompressedData);
            Assert.Equal(data, uncompressedData);
        }
    }
}