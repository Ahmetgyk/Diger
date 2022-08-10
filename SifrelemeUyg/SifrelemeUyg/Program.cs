using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Timer = System.Timers.Timer;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Serialization;

namespace SifrelemeUyg
{
    public class RsaEnc
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RsaEnc()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }

        public string publicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();
        }

        public string Encrypt(string plainText)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);

            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);
            return Convert.ToBase64String(cypher);
        }

        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);
            var plainext = csp.Decrypt(dataBytes, false);
            return Encoding.Unicode.GetString(plainext);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            RsaEnc rs = new RsaEnc();
            string cypher = string.Empty;
            Console.WriteLine($"publicKey: \n {rs.publicKeyString()}\n");

            Console.WriteLine("enter your text to encrypt");
            var text = Console.ReadLine();
            if(text != String.Empty)
            {
                var cyrpher = rs.Encrypt(text);
                Console.WriteLine($"Cyrpher Text:\n{cyrpher}\n");
            }

            Console.WriteLine("press enter to decrypt");
            Console.ReadLine();
            var plaintext = rs.Decrypt(cypher);
            Console.WriteLine("Decrypted Text \n");
            Console.WriteLine(plaintext);
            Console.ReadLine();
        }
    }
}
