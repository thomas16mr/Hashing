using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sodium;

namespace Hashing
{
    class Argon2_hasher
    {
        public Argon2_hasher(){}

        public static string[] GenerateHash(string input,string salt)
        {
            byte[] saltArray;
            byte[] inputToBytes = Encoding.Default.GetBytes(input);

            if(string.IsNullOrEmpty(salt))
            {
                saltArray = PasswordHash.ArgonGenerateSalt();
                //Console.WriteLine(saltArray);
            }
            else
            {
                saltArray = new byte[salt.Length];
                saltArray = Encoding.Default.GetBytes(salt);
            }

            byte[] hash = PasswordHash.ArgonHashBinary(inputToBytes, saltArray, PasswordHash.StrengthArgon.Interactive);

            string resultHash = BitConverter.ToString(hash);
            resultHash = resultHash.Replace("-", "");
            resultHash = resultHash.ToLower();

            string resultSalt = BitConverter.ToString(saltArray);
            resultSalt = resultSalt.Replace("-", "");
            resultSalt = resultSalt.ToLower();

            string[] resultArray = new string[2];
            resultArray[0] = resultHash;
            resultArray[1] = resultSalt;

            //returneme dvojicu hash - salt
            return resultArray;
        }

        public bool VerifyHash(string password, string hash,string salt)
        {

            string[] get = GenerateHash(password, salt);

            StringComparer sc = StringComparer.OrdinalIgnoreCase;

            if (sc.Compare(hash, get[0]) == 1)
            {
                return false;
            }

            else return true;

        }
    }
}
