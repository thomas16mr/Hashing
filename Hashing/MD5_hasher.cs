using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Hashing
{   
    class MD5_hasher
    {
       public MD5_hasher()
        {

        }

        /// <summary>
        /// Funkcia generuje cisty hash MD5 bez saltu
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string GenerateHashWithoutSalt(string input)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] tmp = md5.ComputeHash(Encoding.Default.GetBytes(input));

            string result = Convert.ToBase64String(tmp);
            return result;

        }
        /// <summary>
        /// Funkcia generuje hash s pouzitim MD5(pwd,sal)
        /// ked defaultne nezadame salt, funkcia si vygeneruje salt dlzky 4-8
        /// </summary>
        /// <param name="input"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static string[] GenerateHashWithSalt(string input,string salt)
        {
            byte[] saltArray;

            //ked prvy krat generujeme hash je jednoznacne ze nedostaneme salt ako vstupny parameter funkcie, musime si vytvorit manualne
            if (string.IsNullOrEmpty(salt))
            {

                int maxSaltLength = 8;

                Random random = new Random();
                int saltLength = random.Next(maxSaltLength, maxSaltLength);

                saltArray = new byte[saltLength];

                RNGCryptoServiceProvider randNumGen = new RNGCryptoServiceProvider();
                randNumGen.GetNonZeroBytes(saltArray);

            }
            // v tomto pripade dostaneme salt ako parameter, len potrebujeme dat do tvaru byte array lebo funckia potrebuje

            else
            {
                saltArray = Encoding.Default.GetBytes(salt);
            }


            string sb = input + Encoding.Default.GetString(saltArray);
            
            byte[] inputWithSalt = Encoding.Default.GetBytes(sb);

            //zacneme hashovat
            using (MD5 md5Hash = MD5.Create())
            {

                byte[] tmp = md5Hash.ComputeHash(inputWithSalt);

            
                //result array obsahuje vysledny hash a salt ktore chceme vratit
                string[] resultArray = new string[2];

                string resultHash = BitConverter.ToString(tmp);
                resultHash = resultHash.Replace("-", "");
                resultHash = resultHash.ToLower();

                string resultSalt = BitConverter.ToString(saltArray);
                resultSalt = resultSalt.Replace("-", "");
                resultSalt = resultSalt.ToLower();

                resultArray[0] = resultHash;
                resultArray[1] = resultSalt;

            //returneme dvojicu hash - salt
            return resultArray;
            }
        }

        /// <summary>
        /// Funkcia verifykuje ci zadane haslo a hash su identicke
        /// Verifykuje iba MD5 hash bez saltu
        /// </summary>
        /// <param name="input"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public bool verifyMd5HashWithoutSalt(string input, string hash)
        {
            string inputHash = GenerateHashWithoutSalt(input);

            StringComparer SC = StringComparer.OrdinalIgnoreCase;

            if (SC.Compare(inputHash, hash) == 1)
            {
                return false;
            }
            else return true;

            
        }
    }
}
