using System;
using System.Linq;
using System.Security.Cryptography;
using SimpleCryptography.Business.CompressionServices;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Data.KeyResults;

namespace SimpleCryptography.Business.EncryptionServices
{
    public class AesGcmService : BaseEncryptionService
    {
        private const int TheTagSize = 16;
        private const int TheNonceSize = 12;
        private const int TheKeySize = 32;

        private readonly IGzipCompressionService _gzipCompressionService;

        public AesGcmService()
        {
            _gzipCompressionService = new GzipCompressionService();
        }
        
        public override IKeyResult CreateKeyResult()
        {
            var key = new byte[TheKeySize];
            RandomNumberGenerator.Fill(key);
            return new AesKeyResult() {Key = Convert.ToBase64String(key)};
        }

        protected override byte[] Encrypt(byte[] key, byte[] data)
        {
            //Compresses the supplied data with GZIP before we encrypt it
            data = _gzipCompressionService.Compress(data);

            // Create a 16-byte tag
            var tag = new byte[TheTagSize];
            RandomNumberGenerator.Fill(tag);

            // Create a 12-byte nonce
            var nonce = new byte[TheNonceSize];
            RandomNumberGenerator.Fill(nonce);

            //Stores the results of the encrypted bytes
            byte[] encryptedData = new byte[data.Length];

            //Runs the aes gcm encryption based on the supplied parameters
            using (AesGcm service = new AesGcm(key))
            {
                service.Encrypt(nonce, data, encryptedData, tag);
            }

            //Adds the tag and nonce to the encrypted data
            var returned = tag.Concat(nonce.Concat(encryptedData));

            // Return the encrypted bytes
            return returned.ToArray();
        }

        protected override byte[] Decrypt(byte[] key, byte[] encryptedData)
        {
            //Pulls out the tag from the encrypted data
            byte[] tag = encryptedData[..TheTagSize];

            //Pulls out the nonce from the encrypted data
            byte[] nonce = encryptedData[TheTagSize..(TheTagSize + TheNonceSize)];

            //Removes the tag and nonce from the encrypted data
            encryptedData = encryptedData[(TheTagSize + TheNonceSize)..];

            //Stores the results of the decrypted bytes
            byte[] decryptedData = new byte[encryptedData.Length];

            //Runs the aes gcm decryption based on the supplied parameters
            using (AesGcm service = new AesGcm(key))
            {
                service.Decrypt(nonce, encryptedData, tag, decryptedData);
            }

            //Decompress the supplied data with GZIP after its been decrypted
            decryptedData = _gzipCompressionService.Decompress(decryptedData);

            //Returns the decrypted data
            return decryptedData;
        }
    }
}