namespace Crypto.Interfaces;

///<summary> расширение ключа: генерация раунд ключей из исх ключа </summary>

public interface IKeyExpansion
{
    byte[][] GenerateRoundKeys(byte[] key);
} 