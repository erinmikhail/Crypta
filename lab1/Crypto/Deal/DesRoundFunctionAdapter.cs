using System.Buffers.Binary;
using System.Collections.Concurrent;
using Crypto.Des;
using Crypto.Interfaces;

namespace Crypto.Deal;


public sealed class DesRoundFunctionAdapter : IRoundFunction
{
    private const int MaxCachedKeys = 64;

    private readonly ConcurrentDictionary<ulong, DesCipher> _cache = new();

    public byte[] Transform(byte[] block, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (block.Length != 8)
            throw new ArgumentException("Вход функции F DEAL — половина блока, 64 бита (8 байт).", nameof(block));

        if (roundKey.Length != DesCipher.KeySize)
            throw new ArgumentException("Раундовый ключ DEAL — ключ DES, 64 бита (8 байт).", nameof(roundKey));

        return GetCipher(roundKey).EncryptBlock(block);
    }

    /// <summary>Возвращает DES, уже настроенный на этот ключ: из кэша или новый.</summary>
    private DesCipher GetCipher(byte[] roundKey)
    {
        ulong id = BinaryPrimitives.ReadUInt64BigEndian(roundKey);   // 8 байт к - 1 число

        if (_cache.TryGetValue(id, out DesCipher? cached))
            return cached;

        if (_cache.Count >= MaxCachedKeys)
            _cache.Clear();   // защита

        var des = new DesCipher();
        des.SetKey(roundKey);

        return _cache.GetOrAdd(id, des);
    }
}
