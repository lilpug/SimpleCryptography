using SimpleCryptography.Data.Interfaces;

namespace SimpleCryptography.Data.KeyResults
{
    public class RsaKeyResult : IKeyResult
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}