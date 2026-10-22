namespace Crypto.Interfaces;


public interface ISymmetricCipher
{
    /// <summary>Размер блока в байтах DES-8, DEAL-16</summary>
    int BlockSize { get; }

    /// <summary>генер и запом раунд ключ из ключа шифр-ия</summary>
    /// <param name="key">ключ шифр-ия</param>
    void SetKey(byte[] key);

    /// <summary>Шифр 1 блок len BlockSize</summary>
    /// <returns>Зашифр блок</returns>
    byte[] EncryptBlock(byte[] block);

    /// <summary>Дешифр 1 блок len BlockSize</summary>
    /// <returns>Расшифр блок</returns>
    byte[] DecryptBlock(byte[] block);
}