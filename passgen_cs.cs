// passgen_cs.cs — генератор паролей с настраиваемыми правилами на C#

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class PasswordGenerator
{
    private class Config
    {
        public int DefaultLength { get; set; } = 16;
        public bool UseLetters { get; set; } = true;
        public bool UseDigits { get; set; } = true;
        public bool UseSpecial { get; set; } = true;
        public bool ExcludeSimilar { get; set; } = false;
        public bool ExcludeAmbiguous { get; set; } = false;
    }

    private Config config = new Config();
    private RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

    public PasswordGenerator()
    {
        LoadConfig();
    }

    private void LoadConfig()
    {
        if (File.Exists("passgen_config.json"))
        {
            string json = File.ReadAllText("passgen_config.json");
            config = JsonSerializer.Deserialize<Config>(json) ?? new Config();
        }
        else
        {
            SaveConfig();
        }
    }

    private void SaveConfig()
    {
        string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText("passgen_config.json", json);
    }

    public string Generate(int length, bool letters, bool digits, bool special,
                           bool exclSimilar, bool exclAmbiguous)
    {
        string charSet = "";
        if (letters) charSet += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (digits) charSet += "0123456789";
        if (special) charSet += "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

        if (exclSimilar)
        {
            foreach (char c in "O0Il1")
                charSet = charSet.Replace(c.ToString(), "");
        }
        if (exclAmbiguous)
        {
            foreach (char c in "{}[]()/\\\"'`~,;:.<>")
                charSet = charSet.Replace(c.ToString(), "");
        }
        if (string.IsNullOrEmpty(charSet))
            throw new ArgumentException("Нет доступных символов");

        byte[] data = new byte[length];
        rng.GetBytes(data);
        char[] password = new char[length];
        for (int i = 0; i < length; ++i)
        {
            password[i] = charSet[data[i] % charSet.Length];
        }
        return new string(password);
    }

    public double Entropy(string password)
    {
        var unique = new HashSet<char>(password);
        double perChar = Math.Log(unique.Count, 2);
        return perChar * password.Length;
    }

    public double CrackTime(double entropy)
    {
        return Math.Pow(2, entropy) / 1e9 / (60 * 60 * 24 * 365.25);
    }

    public void Interactive()
    {
        Console.WriteLine("🔐 PassGen Pro — C# Edition");
        Console.Write($"Длина пароля (по умолчанию {config.DefaultLength}): ");
        string input = Console.ReadLine();
        if (!string.IsNullOrEmpty(input)) config.DefaultLength = int.Parse(input);
        Console.Write("Использовать буквы? (y/n, по умолчанию y): ");
        input = Console.ReadLine();
        if (input == "n") config.UseLetters = false;
        Console.Write("Использовать цифры? (y/n, по умолчанию y): ");
        input = Console.ReadLine();
        if (input == "n") config.UseDigits = false;
        Console.Write("Использовать спецсимволы? (y/n, по умолчанию y): ");
        input = Console.ReadLine();
        if (input == "n") config.UseSpecial = false;
        Console.Write("Исключить похожие? (y/n, по умолчанию n): ");
        input = Console.ReadLine();
        config.ExcludeSimilar = (input == "y");
        Console.Write("Исключить двусмысленные? (y/n, по умолчанию n): ");
        input = Console.ReadLine();
        config.ExcludeAmbiguous = (input == "y");
        Console.Write("Количество паролей (по умолчанию 1): ");
        input = Console.ReadLine();
        int count = string.IsNullOrEmpty(input) ? 1 : int.Parse(input);
        SaveConfig();

        for (int i = 0; i < count; ++i)
        {
            try
            {
                string pwd = Generate(config.DefaultLength, config.UseLetters, config.UseDigits,
                                      config.UseSpecial, config.ExcludeSimilar, config.ExcludeAmbiguous);
                double ent = Entropy(pwd);
                double years = CrackTime(ent);
                Console.WriteLine($"{i+1}) {pwd}");
                Console.WriteLine($"   Энтропия: {ent:F1} бит, время взлома: ~ {years:E2} лет");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Ошибка: {e.Message}");
            }
        }
    }

    public static void Main(string[] args)
    {
        var pg = new PasswordGenerator();
        if (args.Length == 0 || (args.Length == 1 && args[0] == "--interactive"))
        {
            pg.Interactive();
            return;
        }

        int length = pg.config.DefaultLength, count = 1;
        bool letters = false, digits = false, special = false, all = false;
        bool exclSimilar = false, exclAmbiguous = false;
        for (int i = 0; i < args.Length; ++i)
        {
            if (args[i] == "-l" || args[i] == "--length")
                length = int.Parse(args[++i]);
            else if (args[i] == "-c" || args[i] == "--count")
                count = int.Parse(args[++i]);
            else if (args[i] == "--letters") letters = true;
            else if (args[i] == "--digits") digits = true;
            else if (args[i] == "--special") special = true;
            else if (args[i] == "--all") all = true;
            else if (args[i] == "--exclude-similar") exclSimilar = true;
            else if (args[i] == "--exclude-ambiguous") exclAmbiguous = true;
        }
        bool useLetters = all || letters || pg.config.UseLetters;
        bool useDigits = all || digits || pg.config.UseDigits;
        bool useSpecial = all || special || pg.config.UseSpecial;
        bool exSim = exclSimilar || pg.config.ExcludeSimilar;
        bool exAmb = exclAmbiguous || pg.config.ExcludeAmbiguous;

        for (int i = 0; i < count; ++i)
        {
            try
            {
                string pwd = pg.Generate(length, useLetters, useDigits, useSpecial, exSim, exAmb);
                double ent = pg.Entropy(pwd);
                double years = pg.CrackTime(ent);
                Console.WriteLine($"{i+1}) {pwd}");
                if (count == 1)
                    Console.WriteLine($"Энтропия: {ent:F1} бит, время взлома: ~ {years:E2} лет");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Ошибка: {e.Message}");
            }
        }
    }
}
