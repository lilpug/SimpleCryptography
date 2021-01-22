using System;

namespace SimpleCryptography.Data.Interfaces
{
    public interface IMessageAuthenticationService
    {
        byte[] SignDataToBytes(string key, byte[] data, TimeSpan? expirePeriod = null);
        byte[] SignDataToBytes(string key, string data, TimeSpan? expirePeriod = null);
        string SignDataToString(string key, byte[] data, TimeSpan? expirePeriod = null);
        string SignDataToString(string key, string data, TimeSpan? expirePeriod = null);
        byte[] VerifyDataToBytes(string key, byte[] data, bool validateExpirationPeriod = false);
        byte[] VerifyDataToBytes(string key, string data, bool validateExpirationPeriod = false);
        string VerifyDataToString(string key, string data, bool validateExpirationPeriod = false);
        string VerifyDataToString(string key, byte[] data, bool validateExpirationPeriod = false);
    }
}