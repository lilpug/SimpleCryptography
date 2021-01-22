using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Data.KeyResults
{
    public class AesKeyResult : IKeyResult
    {
        public string Key { get; set; }
    }
}