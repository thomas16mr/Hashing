using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sodium;
using System.Net;
using System.IO;
using System.Collections.Specialized;
using Newtonsoft;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace Hashing
{
    class Program
    {
        // public Listy do ktoreho ulozime dvojice meno,heslo
        // jeden list pre input a druhy pre output
        public static List<Tuple<string, string>> users = new List<Tuple<string, string>>();
        public static List<Tuple<string, string>> output = new List<Tuple<string, string>>();
        public static int typ = 0;

        // Funkcia nacita dvojice meno,heslo zo suboru a ulozi ich do listu
        //ked pouzivatel zadal zlu cestu alebo subor je pouzivany inym programov
        // funkcia ohlasi chybu a vypne program
        public static void nacitaj(string path)
        {
            try
            {
                int c = 0;
                string[] lines = System.IO.File.ReadAllLines(@path);
                foreach (string s in lines)
                {
                    string[] tmp = s.Split(';');

                    users.Add(new Tuple<string, string>(tmp[0], tmp[1]));
                    c++;

                }
            }
            catch
            {
                Console.WriteLine("Chyba pri otvarani súboru!");
                Console.WriteLine("Skontrolujte cestu, alebo ci subor nie je pouzivany inou aplikaciou");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }
        }


        // Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou Argon2 a posiela request na server kde sa ulozi hash do databazy        
        public static void naplnArgon()
        {
            foreach (Tuple<string, string> t in users)
            {
                string[] get = Argon2_hasher.GenerateHash(t.Item2, "");

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("2");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();

                ConnectionManager.SendData("https://147.175.98.36/insert.php", json);
            }
        }


        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou MD5 so saltom a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        public static void naplnMD5()
        {
            foreach (Tuple<string, string> t in users)
            {

                string[] get = MD5_hasher.GenerateHashWithSalt(t.Item2, "");

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("1");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                //Console.WriteLine(json);
                ConnectionManager.SendData("https://147.175.98.36/insert.php", json);

            }
        }

        /// <summary>
        /// Funkcia prejde cely list dvojic meno,heslo , zahashuje heslo pomocou PBKDF2 a posiela request na server kde sa ulozi hash do databazy
        /// </summary>
        static void naplnPBKDF()
        {
            foreach (Tuple<string, string> t in users)
            {

                string[] get = PKDBF2_hasher.GenerateHash(t.Item2, "");

                JArray array = new JArray();
                array.Add(t.Item1);
                array.Add(get[0]);
                array.Add(get[1]);
                array.Add("3");

                JObject o = new JObject();
                o["MyArray"] = array;

                string json = o.ToString();
                //Console.WriteLine(json);
                ConnectionManager.SendData("https://147.175.98.36/insert.php", json);
            }
        }


        public static void md5Plain(int n)
        {

            for (int i = 0; i < n; i++)
            {
                JArray array = new JArray();
                array.Add("1");
                array.Add(users[i % Program.users.Count].Item1);
                array.Add(users[i % Program.users.Count].Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }


        public static void argon2Plain(int n)
        {
            for (int i = 0; i < n; i++)
            {
                JArray array = new JArray();
                array.Add("2");
                array.Add(users[i % Program.users.Count].Item1);
                array.Add(users[i % Program.users.Count].Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void pkbdfPlain(int n)
        {
            for (int i = 0; i < n; i++)
            {
                JArray array = new JArray();
                array.Add("3");
                array.Add(users[i % Program.users.Count].Item1);
                array.Add(users[i % Program.users.Count].Item2);

                JObject o = new JObject();
                o["MyArray"] = array;
                string json = o.ToString();
                ConnectionManager.SendData("https://147.175.98.36/verifyWhashing.php", json);
            }
        }

        public static void md5QuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {
                string[] postData = new string[3];
                postData[0] = "1";
                postData[1] = users[i % Program.users.Count].Item1;
                postData[2] = users[i % Program.users.Count].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }
        public static void argonQuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {

                string[] postData = new string[3];
                postData[0] = "2";
                postData[1] = users[i % Program.users.Count].Item1;
                postData[2] = users[i % Program.users.Count].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }

        public static void pbkdfQuerySalt(int n)
        {
            for (int i = 0; i < n; i++)
            {
                string[] postData = new string[3];
                postData[0] = "3";
                postData[1] = users[i % Program.users.Count].Item1;
                postData[2] = users[i % Program.users.Count].Item2;
                ConnectionManager.SendData2("https://147.175.98.36/fetch.php", postData);
            }
        }

        public static void uloz()
        {
            try
            {
                foreach (Tuple<string, string> s in output)
                {
                    using (StreamWriter writetext = File.AppendText("write.csv"))
                    {
                        writetext.WriteLine(s.Item1 + ";" + s.Item2);
                    }
                }
                Console.WriteLine("Zapis do suboru je uspesny");
            }
            catch
            {
                Console.WriteLine("Zapis do suboru je neuspesni!");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();

            }

        }

        public static void send(object n)
        {
            int nRequests = (int)n;
            

            switch(Program.typ)
            {
                case 1:
                    md5Plain(nRequests);
                    break;
                case 2:
                    argon2Plain(nRequests);
                    break;
                case 3:
                    pkbdfPlain(nRequests);
                    break;
                case 4:
                    md5QuerySalt(nRequests);
                    break;
                case 5:
                    argonQuerySalt(nRequests);
                    break;
                case 6:
                    pbkdfQuerySalt(nRequests);
                    break;
                default:
                    Console.WriteLine("Niekde sa nastala chyba, zopakujte znova!!");
                    System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                    proc.Kill();
                    break;
            }      
        }

        public static void startThreading(int pocetT,int n)
        {
            for (int i = 0; i < pocetT; i++)
            {
                var thread = new System.Threading.Thread(new ParameterizedThreadStart(send));
                thread.Start(n);
                thread.Join();
            }
        }

        static void Main(string[] args)
        {

            // nacitaj(args[0]);
            int pocetTredov = 1;
            int pocetRequestov = 1;
            int j = 0;
            int k = 1;
            int n = 0;
            // n = pocetRequestov / pocetTredov;
            //// Program.typ = 1;

            //     for (int i = 0; i < pocetTredov; i++)
            //     {
            //         var thread = new System.Threading.Thread(new ParameterizedThreadStart(send));

            //         thread.Start(n);
            //         thread.Join();
            // }


            if (args.Length > 0)
             {
                 nacitaj(args[0]);
                 if (args.Length == 3)
                 {
                     if (args[1] == "0")
                     {
                         if (args[2] == "1")
                         {
                             naplnMD5();

                         }
                         else if (args[2] == "2")
                         {
                             naplnArgon();
                         }
                         else if (args[2] == "3")
                         {
                             naplnPBKDF();
                         }
                         else
                         {
                             Console.WriteLine("Zle ste zadali treti parameter, takato opcia neexistuje!!");
                             System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                             proc.Kill();
                         }
                         Console.WriteLine("Press any key");
                         Console.ReadKey();
                     }
                     else
                     {
                         Console.WriteLine("Druhy parameter je zly!!");
                         Console.WriteLine("Pre naplnenie databazy potrebujeme 3 parametre: cesta k suboru, 0 pre naplnenie databazy, cislo databazy");
                         System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                         proc.Kill();
                     }
                 }
                 else if (args.Length == 5)
                 {
                     if (args[1] == "1")
                     {
                         if (args[2] == "1")
                         {
                             Program.typ = 1;

                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;

                             try
                             {
                                startThreading(pocetTredov, n);

                             }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }

                         }
                         else if (args[2] == "2")
                         {
                             Program.typ = 2;
                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;

                             try
                             {
                                startThreading(pocetTredov, n);
                            }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }
                         }
                         else if (args[2] == "3")
                         {
                             Program.typ = 3;
                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;

                             try
                             {
                                startThreading(pocetTredov, n);
                            }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }
                         }
                         else
                         {
                             Console.WriteLine("Treti parameter je zly!!");
                             Console.WriteLine("Pri tejto kombinacii (5 parametrov) musi to byt 1, 2 alebo 3");
                             System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                             proc.Kill();
                         }
                     }
                     else if (args[1] == "2")
                     {
                         if (args[2] == "1")
                         {
                             Program.typ = 4;
                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;

                             try
                             {
                                startThreading(pocetTredov, n);
                            }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }
                         }
                         else if (args[2] == "2")
                         {
                             Program.typ = 5;
                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;
                             try
                             {
                                startThreading(pocetTredov, n);
                            }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }
                         }
                         else if (args[2] == "3")
                         {
                             Program.typ = 6;
                             if (Int32.TryParse(args[3], out j))
                                 pocetRequestov = j;
                             else
                             {
                                 Console.WriteLine("Chyba!! stvrty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }

                             if (Int32.TryParse(args[4], out k))
                                 pocetTredov = k;
                             else
                             {
                                 Console.WriteLine("Chyba!! piaty parameter nie je cislo");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();
                             }
                             n = pocetRequestov / pocetTredov;

                             try
                             {
                                startThreading(pocetTredov, n);
                            }
                             catch
                             {
                                 Console.WriteLine("Chyba sa nastala s vlaknami!!");
                                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                                 proc.Kill();

                             }
                         }
                         else
                         {
                             Console.WriteLine("Treti parameter je zly!!");
                             Console.WriteLine("Pri tejto kombinacii (5 parametrov) musi to byt 1, 2 alebo 3");
                         }

                     }
                     else
                     {
                         Console.WriteLine("Druhy parameter je zly!!");
                         Console.WriteLine("Pri tejto kombinacii (5 parametrov) musi to bit 1 alebo 2");
                         System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                         proc.Kill();
                     }

                 }
                 else
                 {
                     Console.WriteLine("Tato aplikacia potrebuje 3 alebo 5 parametrov!!");
                     Console.WriteLine("Skontrolujte, ci ste zadali dobre");
                     System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                     proc.Kill();
                 }

             }
             else
             {
                 Console.WriteLine("Nezadali ste ziadne validne parametre");
                 System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                 proc.Kill();
             }
            Console.ReadKey();
            uloz();


        }
    }
} 

