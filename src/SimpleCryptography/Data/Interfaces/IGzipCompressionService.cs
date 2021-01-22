namespace SimpleCryptography.Data.Interfaces
{
    public interface IGzipCompressionService
    {
        byte[] Decompress(byte[] data);
        byte[] Compress(byte[] data);
    }
}