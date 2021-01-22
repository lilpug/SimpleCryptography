namespace SimpleCryptography.Data.Interfaces
{
    public interface IEncryptionService
    {
        IKeyResult CreateKeyResult();
        string EncryptToString(string key, object data);
        byte[] EncryptToBytes(string key, object data);
        T DecryptToType<T>(string key, string encryptedData);
        T DecryptToType<T>(string key, byte[] encryptedData);
    }
}