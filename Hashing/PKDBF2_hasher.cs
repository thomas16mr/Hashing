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

        //funckia hashuje zadane haslo
        //ked nezdame salt tak vyrobi
        //vrati vysledny hash aj salt vo forme hexa cisla
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

            string resultHash = BitConverter.ToString(hash);
            resultHash = resultHash.Replace("-", "");
            resultHash = resultHash.ToLower();

            string resultSalt = BitConverter.ToString(saltArray);
            resultSalt = resultSalt.Replace("-", "");
            resultSalt = resultSalt.ToLower();

            string [] resultArray = new string[2];
            resultArray[0] = resultHash;
            resultArray[1] = resultSalt;

            //returneme dvojicu hash - salt
            return resultArray;
        }         
    }
}
