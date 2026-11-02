namespace Crypto.Modes;


internal interface ICipherModeProcessor
{
    void Encrypt(byte[] buffer);
    void Decrypt(byte[] buffer);
}