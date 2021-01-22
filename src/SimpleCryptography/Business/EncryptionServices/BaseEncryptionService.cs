using System;
using System.Text.Json;
using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Business.EncryptionServices
{
    public abstract class BaseEncryptionService : IEncryptionService
    {
        public abstract IKeyResult CreateKeyResult();
        
        public string EncryptToString(string key, object data)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }
            
            _ = data ?? throw new ArgumentNullException($"{nameof(data)} is required.");
            
            //Converts the key back into byte format for processing
            var theKey = Convert.FromBase64String(key);
            
            //Serialises the data into a byte[]
            byte[] theData = JsonSerializer.SerializeToUtf8Bytes(data);

            //Encrypts the serialised data
            byte[] returnData = Encrypt(theKey, theData);

            //Returns a base64 string as its an encrypted byte[]
            return Convert.ToBase64String(returnData);
        }

        public byte[] EncryptToBytes(string key, object data)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }
            
            _ = data ?? throw new ArgumentNullException($"{nameof(data)} is required.");
            
            //Converts the key back into byte format for processing
            var theKey = Convert.FromBase64String(key);
            
            //Serialises the data into a byte[]
            byte[] theData = JsonSerializer.SerializeToUtf8Bytes(data);

            //Encrypts the data and returns it as a byte[]
            return Encrypt(theKey, theData);
        }
        
        public T DecryptToType<T>(string key, string encryptedData)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }
            
            //Checks if the encrypted data is empty
            if (string.IsNullOrWhiteSpace(encryptedData))
            {
                throw new ArgumentNullException($"{nameof(encryptedData)} is required.");
            }
            
            //Converts the key back into byte format for processing
            var byteEncryptedData = Convert.FromBase64String(encryptedData);

            //Converts the key back into byte format for processing
            var theKey = Convert.FromBase64String(key);
            
            //Decrypts the data and puts it into the variable
            var decryptedData = Decrypt(theKey, byteEncryptedData);

            //Returns the deserialised byte[] back into the object type it was originally
            return JsonSerializer.Deserialize<T>(decryptedData);
        }
        
        public T DecryptToType<T>(string key, byte[] encryptedData)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }
            
            //Checks if the encrypted data is empty
            if (encryptedData == null || encryptedData.Length == 0)
            {
                throw new ArgumentNullException($"{nameof(encryptedData)} is required.");
            }
            
            //Converts the key back into byte format for processing
            var theKey = Convert.FromBase64String(key);
            
            //Decrypts the data and puts it into the variable
            var decryptedData = Decrypt(theKey, encryptedData);

            //Returns the deserialised byte[] back into the object type it was originally
            return JsonSerializer.Deserialize<T>(decryptedData);
        }

        protected abstract byte[] Encrypt(byte[] key, byte[] data);
        protected abstract byte[] Decrypt(byte[] key, byte[] encryptedData);
    }
}