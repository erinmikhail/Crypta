namespace Crypto.Interfaces;

public interface IRoundFunction
{
    ///<summary> раундовая функция: шифрование блока с помощью раунд ключа </summary>
    byte[] Transform(byte[] block, byte[] roundKey);
}
