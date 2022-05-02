using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace flagDecrypter
{


	class Program
    {
		
        public static string Key = "S1hNZ2tQdFJlRkVIWXhKczRMZEIwRmRQVmg3WGxDNEQ=";
        public static string MTX = "ZA+KebBDBS4ANwMEHlyqteMUJ/hwDRcw+YRdtBeIzpihPF0k5KQ+OtGRUxvfFHXKdQr9Fef6lFjLCOHxWubHlcHVJsdYTz8VkkxuzaDfNc4=";
        public static string Flag = "mZzroGSIkpZlwvCwLG0PHQMXzjphDowlbeBayjWJhmYPJ5KiQeUAbcv9SzTnLGpr3uYQ0VvZ02rGlxz71tOXMemdK1DKKY6uX2QfUJW+WlDPcLi1u48xBrhmDcpRaK1G";

        static void Main(string[] args)
        {
            Key = Encoding.UTF8.GetString(Convert.FromBase64String(Key));
            Aes256 aes256 = new Aes256(Key);
            Flag = aes256.Decrypt(Flag);
            Console.WriteLine(Flag);

        }
    }
}
public class Aes256
    {
        private const int KeyLength = 32;
        private const int AuthKeyLength = 64;
        private const int IvLength = 16;
        private const int HmacSha256Length = 32;
        private readonly byte[] _key;
        private readonly byte[] _authKey;
        private static readonly byte[] Salt = Encoding.ASCII.GetBytes("DcRatByqwqdanchun");
    public Aes256(string masterKey)
        {
		if (string.IsNullOrEmpty(masterKey))
            {
                throw new ArgumentException("masterKey can not be null or empty.");
            }
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(masterKey, Salt, 50000);
            _key = rfc2898DeriveBytes.GetBytes(32);
            _authKey = rfc2898DeriveBytes.GetBytes(64);
        }

    public string Decrypt(string input)
    {
        return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(input)));
    }

    public byte[] Decrypt(byte[] input)
    {
        if (input == null)
        {
            throw new ArgumentNullException("input can not be null.");
        }
        MemoryStream memoryStream = new MemoryStream(input);
        AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
        aesCryptoServiceProvider.KeySize = 256;
        aesCryptoServiceProvider.BlockSize = 128;
        aesCryptoServiceProvider.Mode = CipherMode.CBC;
        aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
        aesCryptoServiceProvider.Key = _key;
        using (HMACSHA256 hMACSHA = new HMACSHA256(_authKey))
        {
            byte[] a = hMACSHA.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
            byte[] array = new byte[32];
            memoryStream.Read(array, 0, array.Length);
            if (!AreEqual(a, array))
            {
                throw new CryptographicException("Invalid message authentication code (MAC).");
            }
        }
        byte[] array2 = new byte[16];
        memoryStream.Read(array2, 0, 16);
        aesCryptoServiceProvider.IV = array2;
        CryptoStream cryptoStream = new CryptoStream(memoryStream, aesCryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Read);
        byte[] array3 = new byte[memoryStream.Length - 16 + 1];
        byte[] array4 = new byte[cryptoStream.Read(array3, 0, array3.Length)];
        Buffer.BlockCopy(array3, 0, array4, 0, array4.Length);
        return array4;
    }

    private bool AreEqual(byte[] a1, byte[] a2)
    {
        bool result = true;
        for (int i = 0; i < a1.Length; i++)
        {
            if (a1[i] != a2[i])
            {
                result = false;
            }
        }
        return result;
    }

}










