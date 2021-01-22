using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using SimpleCryptography.Business.CompressionServices;
using SimpleCryptography.Data.Interfaces;
using SimpleCryptography.Data.KeyResults;

namespace SimpleCryptography.Business.EncryptionServices
{
    public class AesCbcService : BaseEncryptionService
    {
        private const int TheIvSize = 16;
        private const int TheKeySizeBits = 256;
        private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
        
        private readonly IGzipCompressionService _gzipCompressionService;

        public AesCbcService()
        {
            _gzipCompressionService = new GzipCompressionService();
        }

        public override IKeyResult CreateKeyResult()
        {
            using var aes = new AesCryptoServiceProvider {KeySize = TheKeySizeBits, Mode = CipherMode};
            aes.GenerateKey();
            return new AesKeyResult() {Key = Convert.ToBase64String(aes.Key)};
        }
   
        protected override byte[] Encrypt(byte[] key, byte[] data)
        {
            //Compresses the supplied data with GZIP before we encrypt it
            data = _gzipCompressionService.Compress(data);

            //Stores the results of the encrypted bytes
            byte[] encrypted = null;

            //Creates an AesCryptoServiceProvider object ready for encrypting     
            using var aes = new AesCryptoServiceProvider {KeySize = TheKeySizeBits, Mode = CipherMode, Key = key};
            
            //Generates the IV
            aes.GenerateIV();
            
            //Creates a encryptor to perform the stream transform
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            //Create the streams used for encryption
            using var memoryStream = new MemoryStream();
            
            using (var csEncrypt = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                //Writes the data to the cryptoStream so that the end result is encrypted using the supplied ICryptoTransform
                csEncrypt.Write(data, 0, data.Length);
            }

            //Puts the byte array from the memory stream which is now encrypted into the variable
            encrypted = memoryStream.ToArray();

            //Adds the IV to the encrypted data
            encrypted = aes.IV.Concat(encrypted).ToArray();
            
            // Return the encrypted bytes
            return encrypted;
        }

        protected override byte[] Decrypt(byte[] key, byte[] encryptedData)
        {
            //Used to store the results of the decrypted byte array
            byte[] decryptedData = null;

            //Pulls out the IV from the encrypted data
            byte[] iv = encryptedData[..TheIvSize];
            
            //Removes the Iv from the encrypted data array
            encryptedData = encryptedData[TheIvSize..];
            
            //Creates an AesCryptoServiceProvider object ready for decrypting
            using var aes = new AesCryptoServiceProvider {KeySize = TheKeySizeBits, Mode = CipherMode, Key = key, IV = iv};

            //Creates a decrytor to perform the stream transform.
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            //Create the streams used for decryption.
            using (var memoryStream = new MemoryStream(encryptedData))
            {
                using (var csDecrypt = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                {
                    //Writes the encrypted data to the cryptoStream so that the end result is decrypted using the supplied ICryptoTransform
                    csDecrypt.Write(encryptedData, 0, encryptedData.Length);
                }

                //Puts the byte array from the memory stream which is now decrypted into the variable
                decryptedData = memoryStream.ToArray();
            }
            
            //Decompress the supplied data with GZIP after its been decrypted
            decryptedData = _gzipCompressionService.Decompress(decryptedData);

            //Returns the decrypted data
            return decryptedData;
        }
    }
}