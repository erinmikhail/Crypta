using Crypto.Interfaces;

namespace Crypto.Modes;

/// <summary>
/// Режим счётчика:(mod 2^(8·n)).
/// CTR — частн случ с дельта = 1; Random Delta — с шагом дельта из доп. параметр.
/// </summary>
internal sealed class CounterMode : ICipherModeProcessor
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _counter;   
    private readonly byte[] _delta;     

    public CounterMode(ISymmetricCipher cipher, byte[] iv, byte[] delta)
    {
        _cipher = cipher;
        _counter = (byte[])iv.Clone();
        _delta = delta;
    }

    public void Encrypt(byte[] buffer) => ApplyKeystream(buffer);

    public void Decrypt(byte[] buffer) => ApplyKeystream(buffer);

    private void ApplyKeystream(byte[] buffer)
    {
        int blockSize = _cipher.BlockSize;
        int blockCount = buffer.Length / blockSize;

        byte[][] counters = new byte[blockCount][];

        for (int i = 0; i < blockCount; i++)
        {
            counters[i] = (byte[])_counter.Clone();
            BlockUtils.AddInPlace(_counter, _delta);
        }

        BlockUtils.ForEachBlock(blockCount, i =>
        {
            byte[] keystream = _cipher.EncryptBlock(counters[i]);                    
            BlockUtils.XorInPlace(buffer.AsSpan(i * blockSize, blockSize), keystream);
        });
    }
}
