using System;
using System.Security.Cryptography;
using SimpleCryptography.Business.CompressionServices;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Data.KeyResults;

namespace SimpleCryptography.Business.EncryptionServices
{
    public class RsaService : BaseEncryptionService
    {
        private readonly RSAEncryptionPadding _paddingType;
        private readonly IGzipCompressionService _gzipCompressionService;

        public RsaService()
        {
            _paddingType = RSAEncryptionPadding.Pkcs1;
            _gzipCompressionService = new GzipCompressionService();
        }
        
        public override IKeyResult CreateKeyResult()
        {
            using var rsaAlg = RSA.Create();
            
            //Obtains the new public and private keys
            var privateKey = rsaAlg.ExportRSAPrivateKey();
            var publicKey = rsaAlg.ExportRSAPublicKey();

            //Converts them into our format and returns them
            return new RsaKeyResult()
            {
                PublicKey = Convert.ToBase64String(publicKey),
                PrivateKey = Convert.ToBase64String(privateKey)
            };
        }
        
        protected override byte[] Encrypt(byte[] key, byte[] data)
        {
            //Compresses the supplied data with GZIP before we encrypt it
            data = _gzipCompressionService.Compress(data);
            
            //Gets the service and key ready
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(key, out _);
            
            //Runs and stores the results of the encrypted bytes
            byte[] encryptedData = rsa.Encrypt(data, _paddingType);
            // Return the encrypted bytes
            return encryptedData;
        }

        protected override byte[] Decrypt(byte[] key, byte[] encryptedData)
        {
            //Gets the service and key ready
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(key, out _);
            
            //Stores the results of the decrypted bytes
            byte[] decryptedData = rsa.Decrypt(encryptedData, _paddingType);
            
            //Decompress the supplied data with GZIP after its been decrypted
            decryptedData = _gzipCompressionService.Decompress(decryptedData);

            //Returns the decrypted data
            return decryptedData;
        }
    }
}