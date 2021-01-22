using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Business.CompressionServices
{
    public class GzipCompressionService : IGzipCompressionService
    {
        public byte[] Decompress(byte[] data)
        {
            //Opens a memorystream with the input data
            using var inputMs = new MemoryStream(data);

            //Opens the GZIP stream in decompress mode using the input memorystream
            using var zipStream = new GZipStream(inputMs, CompressionMode.Decompress);

            //Opens another memorystream for storing the output
            using var outputMs = new MemoryStream();

            //Processes the bytes through the GZIP decompression and copies them to the output memorystream
            zipStream.CopyTo(outputMs);

            //Returns the decompressed byte[] from the output memorystream
            return outputMs.ToArray();
        }

        public byte[] Compress(byte[] data)
        {
            //Opens a memorystream
            using var memoryStream = new MemoryStream();

            //Opens the GZIP stream in compression mode using the memorystream
            using (var zipStream = new GZipStream(memoryStream, CompressionMode.Compress))
            {
                //Writes all the bytes of data to the GZIP stream
                zipStream.Write(data, 0, data.Length);
            }

            //Returns the compressed byte array from the memorystream
            return memoryStream.ToArray();
        }
    }
}