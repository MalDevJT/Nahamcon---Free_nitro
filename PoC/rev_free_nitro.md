using System;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
namespace rev_free_nitro
{
    class Program
    {
        static void Main(string[] args)
        {	
			byte[] data1=cry.decrypters.decrypt(cry.readers.getArr(1), Convert.ToInt32(cry.readers.getStr(1)));
			byte[] data2=cry.decrypters.decrypt(cry.readers.getArr(2), Convert.ToInt32(cry.readers.getStr(2)));
			File.WriteAllBytes("C:\\Users\\User\\Desktop\\ManeySubLib.dll", data1);
			File.WriteAllBytes("C:\\Users\\User\\Desktop\\Client.exe", data2);
		}
    }
}
public class cry
{
	public class readers
	{
		public static string path()
		{
			string data = "C:\\Users\\User\\Desktop\\file.bin"; // of course you must to extract the hexadecimal data from the binary and save it!
			return data;
		}
		public static string getStr(int massive)
		{
			byte[] bytes = File.ReadAllBytes(path());
			return Regex.Match(Encoding.ASCII.GetString(bytes), "<pass1>(.*?)</pass1><pass2>(.*?)</pass2><autorun>(.*?)</autorun>").Groups[massive].Value;
		}

		public static byte[] getArr(int massive)
		{
			byte[] bytes = File.ReadAllBytes(path());
			return decrypters.hextobyte(Regex.Match(Encoding.ASCII.GetString(bytes), "<libArr>(.*?)</libArr><fileArr>(.*?)</fileArr>").Groups[massive].Value);
		}
	}

	public class decrypters
	{
		public static byte[] hextobyte(string hex)
		{
			int length = hex.Length;
			byte[] array = new byte[length / 2];
			for (int i = 0; i < length; i += 2)
			{
				array[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}
			return array;
		}

		public static byte[] decrypt(byte[] data, int pass)
		{
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = (byte)(data[i] ^ pass);
			}
			MemoryStream stream = new MemoryStream(data);
			GZipStream gZipStream = new GZipStream(stream, CompressionMode.Decompress);
			MemoryStream memoryStream = new MemoryStream();
			gZipStream.CopyTo(memoryStream);
			return memoryStream.ToArray();
		}
	}
}
