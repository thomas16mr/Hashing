using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Hashing
{
    class ConnectionManager
        {

        public static int c;
        public ConnectionManager()
        {

        }
        public static void SendData(string URI,string data)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            // the code that you want to measure comes here
            
            // Create a request using a URL that can receive a post.
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            WebRequest request = WebRequest.Create(URI);
           // Set the Method property of the request to POST.
              request.Method = "POST";
                      
            // Create POST data and convert it to a byte array.  
            string postData = "message=" + data;
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            // Set the ContentType property of the WebRequest.  
            request.ContentType = "application/x-www-form-urlencoded";
            // Set the ContentLength property of the WebRequest.  
            request.ContentLength = byteArray.Length;
            // Get the request stream.  
            Stream dataStream = request.GetRequestStream();
            // Write the data to the request stream.  
            dataStream.Write(byteArray, 0, byteArray.Length);
            // Close the Stream object.  
            dataStream.Close();      
           
            WebResponse response = request.GetResponse();
            // Display the status.  
            request.Credentials = CredentialCache.DefaultCredentials;
           // Console.WriteLine(((HttpWebResponse)response).StatusDescription);
            // Get the stream containing content returned by the server.  
             dataStream = response.GetResponseStream();
            // Open the stream using a StreamReader for easy access.  
            StreamReader reader = new StreamReader(dataStream);
            // Read the content.  
            string responseFromServer = reader.ReadToEnd();
            // Display the content.  
            c++;
            watch.Stop();
            var time = watch.Elapsed.TotalSeconds;
            try
            {
                Program.output.Add(new Tuple<string, string>(time.ToString(), responseFromServer));
                Console.WriteLine(c + ": Klient: " + time.ToString() + " Server:" + responseFromServer);
            }
            catch
            {
                Console.WriteLine("Chyba, viac tredov chce pristupit k tomu istemu listu");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }                      
                    
            
            //Console.WriteLine(responseFromServer.Length);
            // Clean up the streams.  
            reader.Close();
            dataStream.Close();
            response.Close();
          
        }

        public static void SendData2(string URI,string []data)
        {
            
            var watch = System.Diagnostics.Stopwatch.StartNew();
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            WebRequest request = WebRequest.Create(URI);            
            request.Method = "POST";
            JArray array = new JArray();
            array.Add(data[0]); //index
            array.Add(data[1]); //login    

            JObject o = new JObject();
            o["MyArray"] = array;
            string json = o.ToString();

            string postData = "message=" + json;
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);     
                     
            request.ContentType = "application/x-www-form-urlencoded";              
            request.ContentLength = byteArray.Length;
            
            Stream dataStream = request.GetRequestStream();             
            dataStream.Write(byteArray, 0, byteArray.Length);            
            dataStream.Close();

            //Odpoved 
            WebResponse response = request.GetResponse();
            request.Credentials = CredentialCache.DefaultCredentials;

            //Console.WriteLine(((HttpWebResponse)response).StatusDescription);
              
            dataStream = response.GetResponseStream();
              
            StreamReader reader = new StreamReader(dataStream);              
            string responseFromServer = reader.ReadToEnd();
            reader.Close();
            dataStream.Close();
            response.Close();

            string[] get = new string[2];

            if (data[0] == "1")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);                            
                get = MD5_hasher.GenerateHashWithSalt(data[2], s);

            }
            if (data[0] == "2")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);
                get = Argon2_hasher.GenerateHash(data[2], s);
            }
            if (data[0] == "3")
            {
                byte[] bytes = new byte[responseFromServer.Length / 2];
                for (var j = 0; j < bytes.Length; j++)
                {
                    bytes[j] = Convert.ToByte(responseFromServer.Substring(j * 2, 2), 16);
                }
                //bytes to string
                string s = Encoding.Default.GetString(bytes);
                get = PKDBF2_hasher.GenerateHash(data[2], s);
            }

            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
             request = WebRequest.Create("https://147.175.98.36/justVerify.php");
             request.Method = "POST";

              array = new JArray();
              array.Add(data[0]);  //index
              array.Add(data[1]);  //login
              array.Add(get[0]);   //hash

            JObject k = new JObject();
            k["MyArray"] = array;
            string jSon = k.ToString();

             postData = "message=" + jSon;
            
             byteArray = Encoding.UTF8.GetBytes(postData);

            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;

             dataStream = request.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            //Odpoved 
             response = request.GetResponse();
            request.Credentials = CredentialCache.DefaultCredentials;

           // Console.WriteLine(((HttpWebResponse)response).StatusDescription);

            dataStream = response.GetResponseStream();

             reader = new StreamReader(dataStream);
             responseFromServer = reader.ReadToEnd();
            watch.Stop();
            var time = watch.Elapsed.TotalSeconds;
            try
            {
                
                Program.output.Add(new Tuple<string, string>(time.ToString(), responseFromServer));
                Console.WriteLine("Klient: " + time.ToString() + " Server: " + responseFromServer);
            }
            catch
            {
                Console.WriteLine("Chyba, viac tredov chce pristupit k tomu istemu listu");
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetCurrentProcess();
                proc.Kill();
            }
            
                   

            reader.Close();
            dataStream.Close();
            response.Close();



        }
    }
}
