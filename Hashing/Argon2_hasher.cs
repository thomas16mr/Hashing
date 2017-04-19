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

            string resultHash = Convert.ToBase64String(hash);
            string resultSalt = Convert.ToBase64String(saltArray);
                    

            string[] result = new string[2];
            result[0] = resultHash;
            result[1] = resultSalt;

            return result; 


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
