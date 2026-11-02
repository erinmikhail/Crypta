using Crypto.Interfaces;
using Crypto.Modes;

namespace Crypto.Feistel;


public sealed class FeistelNetwork : ISymmetricCipher
{
    private readonly IKeyExpansion _keyExpansion;
    private readonly IRoundFunction _roundFunction;
    private byte[][]? _roundKeys;   

    /// <param name="keyExpansion">Генератор раундовых ключей.</param>
    /// <param name="roundFunction">Раундовая функция F: 1\2 блока + раундовый ключ -> 1\2 блока.</param>
    public FeistelNetwork(IKeyExpansion keyExpansion, IRoundFunction roundFunction, int blockSize)
    {
        ArgumentNullException.ThrowIfNull(keyExpansion);
        ArgumentNullException.ThrowIfNull(roundFunction);

        if (blockSize <= 0 || blockSize % 2 != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize),
                "Размер блока сети Фейстеля должен быть положительным чётным числом.");

        _keyExpansion = keyExpansion;
        _roundFunction = roundFunction;
        BlockSize = blockSize;
    }

    public int BlockSize { get; }

    /// <summary>Генерирует и запоминает раундовые ключи.</summary>
    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        byte[][] roundKeys = _keyExpansion.GenerateRoundKeys(key);

        if (roundKeys is null || roundKeys.Length == 0)
            throw new InvalidOperationException("Процедура расширения ключа не вернула раундовых ключей.");

        _roundKeys = roundKeys;
    }

    public byte[] EncryptBlock(byte[] block) => Process(block, reverseKeys: false);

    public byte[] DecryptBlock(byte[] block) => Process(block, reverseKeys: true);

    private byte[] Process(byte[] block, bool reverseKeys)
    {
        byte[][] roundKeys = _roundKeys
            ?? throw new InvalidOperationException("Ключ не задан: сначала вызовите SetKey.");

        ArgumentNullException.ThrowIfNull(block);

        if (block.Length != BlockSize)
            throw new ArgumentException($"Блок должен быть длиной {BlockSize} байт.", nameof(block));

        int half = BlockSize / 2;
        byte[] left = block[..half];  
        byte[] right = block[half..];   

        for (int round = 0; round < roundKeys.Length; round++)
        {

            byte[] roundKey = reverseKeys ? roundKeys[^(round + 1)] : roundKeys[round];

            byte[] f = _roundFunction.Transform(right, roundKey); 

            if (f.Length != half)
                throw new InvalidOperationException(
                    $"Раундовая функция вернула {f.Length} байт, ожидалось {half}.");

            byte[] newRight = (byte[])left.Clone();
            BlockUtils.XorInPlace(newRight, f);                      

            left = right;                                          
            right = newRight;                                      
        }

        byte[] result = new byte[BlockSize];
        right.CopyTo(result, 0);
        left.CopyTo(result, half);
        return result;
    }
}
