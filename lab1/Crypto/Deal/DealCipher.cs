using Crypto.Feistel;
using Crypto.Interfaces;

namespace Crypto.Deal;

/// <summary>Ключ 128/192/256 бит, 6 или 8 раундов.</summary>
public sealed class DealCipher : ISymmetricCipher
{
    private readonly FeistelNetwork _network =
        new(new DealKeyExpansion(), new DesRoundFunctionAdapter(), blockSize: 16);

    public int BlockSize => 16;

    public void SetKey(byte[] key) => _network.SetKey(key);

    public byte[] EncryptBlock(byte[] block) => _network.EncryptBlock(block);

    public byte[] DecryptBlock(byte[] block) => _network.DecryptBlock(block);
}
