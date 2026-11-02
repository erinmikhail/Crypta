using Crypto.Des;
using Crypto.Interfaces;
using Crypto.Modes;

namespace Crypto.Deal;


public sealed class DealKeyExpansion : IKeyExpansion
{
    private static readonly byte[] FixedKey = Convert.FromHexString("1234567890ABCDEF");

    private readonly DesCipher _fixedDes;

    public DealKeyExpansion()
    {
        _fixedDes = new DesCipher();
        _fixedDes.SetKey(FixedKey);
    }

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("Ключ DEAL должен быть длиной 16, 24 или 32 байта.",
                nameof(key));

        int partCount = key.Length / 8;
        int roundCount = partCount == 4 ? 8 : 6;
        byte[][] parts = key.Chunk(8).ToArray();

        byte[][] roundKeys = new byte[roundCount][];
        byte[] previous = new byte[8];

        for (int i = 0; i < roundCount; i++)
        {
            byte[] input = (byte[])parts[i % partCount].Clone();
            BlockUtils.XorInPlace(input, previous);

            if (i >= partCount)
            {
                int bit = 1 << (i - partCount);                    // номер бита константы: 1, 2, 4, 8
                input[(bit - 1) / 8] ^= (byte)(0x80 >> ((bit - 1) % 8));
            }

            roundKeys[i] = _fixedDes.EncryptBlock(input);
            previous = roundKeys[i];
        }

        return roundKeys;
    }
}
