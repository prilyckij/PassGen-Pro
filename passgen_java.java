// passgen_java.java — генератор паролей с настраиваемыми правилами на Java

import java.security.SecureRandom;
import java.util.*;
import java.io.*;

public class PasswordGenerator {
    private static final String CONFIG_FILE = "passgen_config.json";
    private int defaultLength = 16;
    private boolean useLetters = true, useDigits = true, useSpecial = true;
    private boolean excludeSimilar = false, excludeAmbiguous = false;
    private SecureRandom random = new SecureRandom();

    public PasswordGenerator() {
        loadConfig();
    }

    private void loadConfig() {
        try (BufferedReader br = new BufferedReader(new FileReader(CONFIG_FILE))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            String json = sb.toString();
            // упрощённый парсинг (без библиотеки)
            defaultLength = extractInt(json, "default_length", 16);
            useLetters = extractBool(json, "use_letters", true);
            useDigits = extractBool(json, "use_digits", true);
            useSpecial = extractBool(json, "use_special", true);
            excludeSimilar = extractBool(json, "exclude_similar", false);
            excludeAmbiguous = extractBool(json, "exclude_ambiguous", false);
        } catch (IOException e) {
            // defaults
            saveConfig();
        }
    }

    private int extractInt(String json, String key, int def) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx == -1) return def;
        int start = idx + search.length();
        int end = json.indexOf(",", start);
        if (end == -1) end = json.indexOf("}", start);
        try {
            return Integer.parseInt(json.substring(start, end).trim());
        } catch (NumberFormatException e) { return def; }
    }

    private boolean extractBool(String json, String key, boolean def) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx == -1) return def;
        int start = idx + search.length();
        int end = json.indexOf(",", start);
        if (end == -1) end = json.indexOf("}", start);
        String val = json.substring(start, end).trim();
        return val.equals("true");
    }

    private void saveConfig() {
        String json = String.format(
            "{\"default_length\":%d,\"use_letters\":%b,\"use_digits\":%b,\"use_special\":%b,\"exclude_similar\":%b,\"exclude_ambiguous\":%b}",
            defaultLength, useLetters, useDigits, useSpecial, excludeSimilar, excludeAmbiguous);
        try (PrintWriter pw = new PrintWriter(CONFIG_FILE)) {
            pw.println(json);
        } catch (IOException e) {}
    }

    public String generate(int length, boolean letters, boolean digits, boolean special,
                           boolean exclSimilar, boolean exclAmbiguous) {
        StringBuilder charSet = new StringBuilder();
        if (letters) charSet.append("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (digits) charSet.append("0123456789");
        if (special) charSet.append("!@#$%^&*()_+-=[]{}|;:,.<>?/~`");

        if (exclSimilar) {
            for (char c : "O0Il1".toCharArray()) {
                int idx = charSet.indexOf(String.valueOf(c));
                if (idx != -1) charSet.deleteCharAt(idx);
            }
        }
        if (exclAmbiguous) {
            for (char c : "{}[]()/\\\"'`~,;:.<>".toCharArray()) {
                int idx = charSet.indexOf(String.valueOf(c));
                if (idx != -1) charSet.deleteCharAt(idx);
            }
        }
        if (charSet.length() == 0) throw new IllegalArgumentException("Нет доступных символов");

        StringBuilder password = new StringBuilder();
        for (int i=0; i<length; ++i) {
            int idx = random.nextInt(charSet.length());
            password.append(charSet.charAt(idx));
        }
        return password.toString();
    }

    public double entropy(String password) {
        String unique = "";
        for (char c : password.toCharArray()) {
            if (unique.indexOf(c) == -1) unique += c;
        }
        double perChar = Math.log(unique.length()) / Math.log(2);
        return perChar * password.length();
    }

    public double crackTime(double entropy) {
        return Math.pow(2, entropy) / 1e9 / (60*60*24*365.25);
    }

    public void interactive() {
        System.out.println("🔐 PassGen Pro — Java Edition");
        Scanner sc = new Scanner(System.in);
        System.out.print("Длина пароля (по умолчанию " + defaultLength + "): ");
        String input = sc.nextLine();
        if (!input.isEmpty()) defaultLength = Integer.parseInt(input);
        System.out.print("Использовать буквы? (y/n, по умолчанию y): ");
        input = sc.nextLine();
        if (input.equals("n")) useLetters = false;
        System.out.print("Использовать цифры? (y/n, по умолчанию y): ");
        input = sc.nextLine();
        if (input.equals("n")) useDigits = false;
        System.out.print("Использовать спецсимволы? (y/n, по умолчанию y): ");
        input = sc.nextLine();
        if (input.equals("n")) useSpecial = false;
        System.out.print("Исключить похожие? (y/n, по умолчанию n): ");
        input = sc.nextLine();
        excludeSimilar = input.equals("y");
        System.out.print("Исключить двусмысленные? (y/n, по умолчанию n): ");
        input = sc.nextLine();
        excludeAmbiguous = input.equals("y");
        System.out.print("Количество паролей (по умолчанию 1): ");
        input = sc.nextLine();
        int count = input.isEmpty() ? 1 : Integer.parseInt(input);
        saveConfig();

        for (int i=0; i<count; ++i) {
            try {
                String pwd = generate(defaultLength, useLetters, useDigits, useSpecial,
                                      excludeSimilar, excludeAmbiguous);
                double ent = entropy(pwd);
                double years = crackTime(ent);
                System.out.println((i+1) + ") " + pwd);
                System.out.println("   Энтропия: " + ent + " бит, время взлома: ~ " + years + " лет");
            } catch (IllegalArgumentException e) {
                System.err.println("Ошибка: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        PasswordGenerator pg = new PasswordGenerator();
        if (args.length == 0 || (args.length == 1 && args[0].equals("--interactive"))) {
            pg.interactive();
            return;
        }
        // упрощённый парсинг аргументов
        int length = pg.defaultLength, count = 1;
        boolean letters = false, digits = false, special = false, all = false;
        boolean exclSimilar = false, exclAmbiguous = false;
        for (int i=0; i<args.length; ++i) {
            if (args[i].equals("-l") || args[i].equals("--length")) {
                length = Integer.parseInt(args[++i]);
            } else if (args[i].equals("-c") || args[i].equals("--count")) {
                count = Integer.parseInt(args[++i]);
            } else if (args[i].equals("--letters")) letters = true;
            else if (args[i].equals("--digits")) digits = true;
            else if (args[i].equals("--special")) special = true;
            else if (args[i].equals("--all")) all = true;
            else if (args[i].equals("--exclude-similar")) exclSimilar = true;
            else if (args[i].equals("--exclude-ambiguous")) exclAmbiguous = true;
        }
        boolean useLetters = all || letters || pg.useLetters;
        boolean useDigits = all || digits || pg.useDigits;
        boolean useSpecial = all || special || pg.useSpecial;
        boolean exSim = exclSimilar || pg.excludeSimilar;
        boolean exAmb = exclAmbiguous || pg.excludeAmbiguous;

        for (int i=0; i<count; ++i) {
            try {
                String pwd = pg.generate(length, useLetters, useDigits, useSpecial, exSim, exAmb);
                double ent = pg.entropy(pwd);
                double years = pg.crackTime(ent);
                System.out.println((i+1) + ") " + pwd);
                if (count == 1) {
                    System.out.println("Энтропия: " + ent + " бит, время взлома: ~ " + years + " лет");
                }
            } catch (IllegalArgumentException e) {
                System.err.println("Ошибка: " + e.getMessage());
            }
        }
    }
}
