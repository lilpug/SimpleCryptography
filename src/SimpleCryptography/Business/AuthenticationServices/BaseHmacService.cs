using System;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Business.AuthenticationServices
{
    public abstract class BaseHmacService : IMessageAuthenticationService
    {
        private const int TimestampSize = 8;
        
        protected abstract int GetTagSize();
        protected abstract HMAC CreateInstance(byte[] key);
        
        protected byte[] CalculateHash(byte[] key, byte[] data)
        {
            //Generates a new tag using the key and data supplied
            using var hmac = CreateInstance(key);
            return hmac.ComputeHash(data);
        }
        
        protected bool VerifyHash(byte[] key, byte[] data, byte[] tagData)
        {
            //Calculates the new hmac tag
            var newTag = CalculateHash(key, data);
            
            //Compares the old and new tag to see if they match
            return (tagData.SequenceEqual(newTag));
        }

        protected byte[] CoreSignData(string key, byte[] data, TimeSpan? expirePeriod)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }

            //Checks the data is not empty
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException($"{nameof(data)} is required.");
            }
            
            //Converts the key back into byte format for processing
            var theKey = Encoding.Unicode.GetBytes(key);
            
            //Calculates the new hash tag
            var tag = CalculateHash(theKey, data);
            
            //Adds the tag to the original data
            var processedData = data?.Concat(tag)?.ToArray();

            //Checks if the expired flag has been supplied and if so adds the expire information to the data
            if (expirePeriod.HasValue)
            {
                var unixTimestamp = DateTimeOffset.UtcNow.Add(expirePeriod.Value).ToUnixTimeSeconds();
                var timestamp = BitConverter.GetBytes(unixTimestamp);
                processedData = processedData?.Concat(timestamp)?.ToArray();
            }

            //Returns the new processed data
            return processedData;
        }

        protected byte[] CoreVerifyData(string key, byte[] data, bool expirePeriod)
        {
            //Checks the key is not empty
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException($"{nameof(key)} is required.");
            }
            
            //Pulls the tag size
            var tagSize = GetTagSize();
            
            if (data == null)
            {
                throw new ArgumentNullException($"{nameof(data)} is required.");
            }
            else if (data.Length < tagSize)
            {
                throw new ArgumentException("The supplied data is not in a valid hmac format.");
            }
            
            //Converts the key back into byte format for processing
            var theKey = Encoding.Unicode.GetBytes(key);
            
            //Checks if we should process any timestamp prior to verifying it
            if (expirePeriod)
            {
                //pulls out the timestamp information from the data 
                var timestamp = data[^TimestampSize..((data.Length - TimestampSize) + TimestampSize)];
                var unixTimestamp = BitConverter.ToInt64(timestamp, 0);

                //Separates the other data sections from the timestamp bit
                data = data[..^TimestampSize];

                //Puts the timestamp data into a checkable format and checks if its still valid before continuing
                var authenticationTimestamp = DateTimeOffset.FromUnixTimeSeconds(unixTimestamp);
                if (DateTime.UtcNow > authenticationTimestamp)
                {
                    throw new AuthenticationException("The Authentication check failed due to the expiration time.");
                }
            }

            //Pulls out the tag data
            var tag = data[^tagSize..((data.Length-tagSize)+tagSize)];
            
            //Pulls out the original tag without the tag
            data = data[..^tagSize];

            //Verifies the original data's hash matches our pulled out tag
            var result = VerifyHash(theKey, data, tag);
            if (!result)
            {
                throw new AuthenticationException("The Authentication check does not match the original calculation.");
            }

            //Returns the original data as its been verified
            return data;
        }
        
        public byte[] SignDataToBytes(string key, byte[] data, TimeSpan? expirePeriod = null)
        {
            //Runs the main sign process and returns the result
            return CoreSignData(key, data, expirePeriod);
        }
        
        public byte[] SignDataToBytes(string key, string data, TimeSpan? expirePeriod = null)
        {
            //Converts the data into bytes if possible
            var convertedData = !string.IsNullOrWhiteSpace(data) ? Convert.FromBase64String(data) : null;
            
            //Runs the main sign process and returns the result
            return CoreSignData(key, convertedData, expirePeriod);
        }
        
        public string SignDataToString(string key, byte[] data, TimeSpan? expirePeriod = null)
        {
            //Runs the main sign process and returns the result
            var processedData = CoreSignData(key, data, expirePeriod);

            //Returns the result as a base64string
            return Convert.ToBase64String(processedData);
        }
        
        public string SignDataToString(string key, string data, TimeSpan? expirePeriod = null)
        {
            //Converts the data into bytes if possible
            var convertedData = !string.IsNullOrWhiteSpace(data) ? Convert.FromBase64String(data) : null;
            
            //Runs the main sign process and returns the result
            var processedData = CoreSignData(key, convertedData, expirePeriod);

            //Returns the result as a base64string
            return Convert.ToBase64String(processedData);
        }
        
        public byte[] VerifyDataToBytes(string key, byte[] data, bool validateExpirationPeriod = false)
        {
            //Runs the verify process and returns the result
            return CoreVerifyData(key, data, validateExpirationPeriod);
        }
        
        public byte[] VerifyDataToBytes(string key, string data, bool validateExpirationPeriod = false)
        {   
            //Converts the data into bytes if possible
            var convertedData = !string.IsNullOrWhiteSpace(data) ? Convert.FromBase64String(data) : null;
            
            //Runs the verify process and returns the result
            return CoreVerifyData(key, convertedData, validateExpirationPeriod);
        }
        
        public string VerifyDataToString(string key, string data, bool validateExpirationPeriod = false)
        {   
            //Converts the data into bytes if possible
            var convertedData = !string.IsNullOrWhiteSpace(data) ? Convert.FromBase64String(data) : null;
            
            //Runs the verify process and returns the result
            var processedData = CoreVerifyData(key, convertedData, validateExpirationPeriod);

            //Returns the result as a base64string
            return Convert.ToBase64String(processedData);
        }
        
        public string VerifyDataToString(string key, byte[] data, bool validateExpirationPeriod = false)
        {   
            //Runs the verify process and returns the result
            var processedData = CoreVerifyData(key, data, validateExpirationPeriod);

            //Returns the result as a base64string
            return Convert.ToBase64String(processedData);
        } 
    }
}