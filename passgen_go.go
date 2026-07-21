// passgen_go.go — генератор паролей с настраиваемыми правилами на Go

package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
)

type Config struct {
	DefaultLength    int  `json:"default_length"`
	UseLetters       bool `json:"use_letters"`
	UseDigits        bool `json:"use_digits"`
	UseSpecial       bool `json:"use_special"`
	ExcludeSimilar   bool `json:"exclude_similar"`
	ExcludeAmbiguous bool `json:"exclude_ambiguous"`
}

var config Config

func init() {
	loadConfig()
}

func loadConfig() {
	data, err := os.ReadFile("passgen_config.json")
	if err == nil {
		json.Unmarshal(data, &config)
	}
	if config.DefaultLength == 0 {
		config.DefaultLength = 16
		config.UseLetters = true
		config.UseDigits = true
		config.UseSpecial = true
		saveConfig()
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("passgen_config.json", data, 0644)
}

func generatePassword(length int, letters, digits, special, exclSimilar, exclAmbiguous bool) (string, error) {
	var charSet string
	if letters {
		charSet += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if digits {
		charSet += "0123456789"
	}
	if special {
		charSet += "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
	}

	if exclSimilar {
		for _, c := range "O0Il1" {
			charSet = strings.ReplaceAll(charSet, string(c), "")
		}
	}
	if exclAmbiguous {
		for _, c := range "{}[]()/\\\"'`~,;:.<>" {
			charSet = strings.ReplaceAll(charSet, string(c), "")
		}
	}
	if len(charSet) == 0 {
		return "", fmt.Errorf("нет доступных символов")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		password[i] = charSet[int(buf[i])%len(charSet)]
	}
	return string(password), nil
}

func entropy(password string) float64 {
	unique := make(map[rune]bool)
	for _, c := range password {
		unique[c] = true
	}
	perChar := math.Log2(float64(len(unique)))
	return perChar * float64(len(password))
}

func crackTime(entropy float64) float64 {
	return math.Pow(2, entropy) / 1e9 / (60 * 60 * 24 * 365.25)
}

func interactive() {
	fmt.Println("🔐 PassGen Pro — Go Edition")
	var input string
	fmt.Printf("Длина пароля (по умолчанию %d): ", config.DefaultLength)
	fmt.Scanln(&input)
	if input != "" {
		fmt.Sscanf(input, "%d", &config.DefaultLength)
	}
	fmt.Print("Использовать буквы? (y/n, по умолчанию y): ")
	fmt.Scanln(&input)
	if input == "n" {
		config.UseLetters = false
	}
	fmt.Print("Использовать цифры? (y/n, по умолчанию y): ")
	fmt.Scanln(&input)
	if input == "n" {
		config.UseDigits = false
	}
	fmt.Print("Использовать спецсимволы? (y/n, по умолчанию y): ")
	fmt.Scanln(&input)
	if input == "n" {
		config.UseSpecial = false
	}
	fmt.Print("Исключить похожие? (y/n, по умолчанию n): ")
	fmt.Scanln(&input)
	config.ExcludeSimilar = (input == "y")
	fmt.Print("Исключить двусмысленные? (y/n, по умолчанию n): ")
	fmt.Scanln(&input)
	config.ExcludeAmbiguous = (input == "y")
	fmt.Print("Количество паролей (по умолчанию 1): ")
	fmt.Scanln(&input)
	count := 1
	if input != "" {
		fmt.Sscanf(input, "%d", &count)
	}
	saveConfig()

	for i := 0; i < count; i++ {
		pwd, err := generatePassword(config.DefaultLength, config.UseLetters, config.UseDigits,
			config.UseSpecial, config.ExcludeSimilar, config.ExcludeAmbiguous)
		if err != nil {
			fmt.Println("Ошибка:", err)
			return
		}
		ent := entropy(pwd)
		years := crackTime(ent)
		fmt.Printf("%d) %s\n", i+1, pwd)
		fmt.Printf("   Энтропия: %.1f бит, время взлома: ~ %.2e лет\n", ent, years)
	}
}

func main() {
	length := flag.Int("l", config.DefaultLength, "Длина пароля")
	letters := flag.Bool("letters", false, "Буквы")
	digits := flag.Bool("digits", false, "Цифры")
	special := flag.Bool("special", false, "Спецсимволы")
	all := flag.Bool("all", false, "Все типы")
	exclSimilar := flag.Bool("exclude-similar", false, "Исключить похожие")
	exclAmbiguous := flag.Bool("exclude-ambiguous", false, "Исключить двусмысленные")
	count := flag.Int("c", 1, "Количество паролей")
	interactiveMode := flag.Bool("interactive", false, "Интерактивный режим")
	flag.Parse()

	if *interactiveMode || len(os.Args) == 1 {
		interactive()
		return
	}

	useLetters := *all || *letters || config.UseLetters
	useDigits := *all || *digits || config.UseDigits
	useSpecial := *all || *special || config.UseSpecial
	exclSim := *exclSimilar || config.ExcludeSimilar
	exclAmb := *exclAmbiguous || config.ExcludeAmbiguous

	for i := 0; i < *count; i++ {
		pwd, err := generatePassword(*length, useLetters, useDigits, useSpecial, exclSim, exclAmb)
		if err != nil {
			fmt.Println("Ошибка:", err)
			return
		}
		ent := entropy(pwd)
		years := crackTime(ent)
		fmt.Printf("%d) %s\n", i+1, pwd)
		if *count == 1 {
			fmt.Printf("Энтропия: %.1f бит, время взлома: ~ %.2e лет\n", ent, years)
		}
	}
}
