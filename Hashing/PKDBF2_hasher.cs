using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Hashing
{
    class PKDBF2_hasher
    {
        public PKDBF2_hasher() { }

        public static string[] GenerateHash(string pass, string salt)
        {
            byte[] saltArray;
            byte[] inputToBytes = Encoding.Default.GetBytes(pass);

            if (string.IsNullOrEmpty(salt))
            {
                int maxSaltLength = 8;

                Random random = new Random();
                int saltLength = random.Next(maxSaltLength, maxSaltLength);

                saltArray = new byte[saltLength];

                RNGCryptoServiceProvider randNumGen = new RNGCryptoServiceProvider();
                randNumGen.GetNonZeroBytes(saltArray);
               
            }
            else
            {
                saltArray = new byte[salt.Length];
                saltArray = Encoding.Default.GetBytes(salt);
            }

            Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(inputToBytes, saltArray, 1000);

            byte[] hash = pbkdf.GetBytes(16);

            string[] result = new string[2];

            result[0] = Convert.ToBase64String(hash);
            result[1] = Convert.ToBase64String(saltArray);
          //  Console.WriteLine(result[1]);
            return result;
        }


        public bool VerifyHash(string hash, string pass, string salt)
        {

            string[] get = new string[2];
            get = GenerateHash(pass, salt);

            StringComparer sc = StringComparer.OrdinalIgnoreCase;

            if(sc.Compare(hash,get[0]) == 1)
            {
                return false;
            }

            else  return true;
        }
         
    }
}
