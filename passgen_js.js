// passgen_js.js — генератор паролей с настраиваемыми правилами на JavaScript (Node.js)

const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

const configFile = 'passgen_config.json';
let config = {
    defaultLength: 16,
    useLetters: true,
    useDigits: true,
    useSpecial: true,
    excludeSimilar: false,
    excludeAmbiguous: false
};

function loadConfig() {
    try {
        const data = fs.readFileSync(configFile, 'utf8');
        config = { ...config, ...JSON.parse(data) };
    } catch (e) {}
}

function saveConfig() {
    fs.writeFileSync(configFile, JSON.stringify(config, null, 4));
}

function generatePassword(length, letters, digits, special, exclSimilar, exclAmbiguous) {
    let charSet = '';
    if (letters) charSet += 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (digits) charSet += '0123456789';
    if (special) charSet += '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';

    if (exclSimilar) {
        for (const c of 'O0Il1') charSet = charSet.replace(new RegExp(c, 'g'), '');
    }
    if (exclAmbiguous) {
        for (const c of '{}[]()/\\"\'`~,;:.<>') charSet = charSet.replace(new RegExp(c, 'g'), '');
    }
    if (charSet.length === 0) throw new Error('Нет доступных символов');

    const bytes = crypto.randomBytes(length);
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charSet[bytes[i] % charSet.length];
    }
    return password;
}

function entropy(password) {
    const unique = new Set(password);
    const perChar = Math.log2(unique.size);
    return perChar * password.length;
}

function crackTime(entropy) {
    return Math.pow(2, entropy) / 1e9 / (60 * 60 * 24 * 365.25);
}

function interactive() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    console.log('🔐 PassGen Pro — JavaScript Edition');
    rl.question(`Длина пароля (по умолчанию ${config.defaultLength}): `, (answer) => {
        if (answer) config.defaultLength = parseInt(answer);
        rl.question('Использовать буквы? (y/n, по умолчанию y): ', (a) => {
            if (a === 'n') config.useLetters = false;
            rl.question('Использовать цифры? (y/n, по умолчанию y): ', (b) => {
                if (b === 'n') config.useDigits = false;
                rl.question('Использовать спецсимволы? (y/n, по умолчанию y): ', (c) => {
                    if (c === 'n') config.useSpecial = false;
                    rl.question('Исключить похожие? (y/n, по умолчанию n): ', (d) => {
                        config.excludeSimilar = (d === 'y');
                        rl.question('Исключить двусмысленные? (y/n, по умолчанию n): ', (e) => {
                            config.excludeAmbiguous = (e === 'y');
                            rl.question('Количество паролей (по умолчанию 1): ', (f) => {
                                const count = parseInt(f) || 1;
                                saveConfig();
                                for (let i = 0; i < count; i++) {
                                    try {
                                        const pwd = generatePassword(
                                            config.defaultLength,
                                            config.useLetters,
                                            config.useDigits,
                                            config.useSpecial,
                                            config.excludeSimilar,
                                            config.excludeAmbiguous
                                        );
                                        const ent = entropy(pwd);
                                        const years = crackTime(ent);
                                        console.log(`${i+1}) ${pwd}`);
                                        console.log(`   Энтропия: ${ent.toFixed(1)} бит, время взлома: ~ ${years.toExponential(2)} лет`);
                                    } catch (err) {
                                        console.error('Ошибка:', err.message);
                                    }
                                }
                                rl.close();
                            });
                        });
                    });
                });
            });
        });
    });
}

function main() {
    loadConfig();
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes('--interactive')) {
        interactive();
        return;
    }

    let length = config.defaultLength;
    let count = 1;
    let letters = false, digits = false, special = false, all = false;
    let exclSimilar = false, exclAmbiguous = false;
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-l' || args[i] === '--length') {
            length = parseInt(args[++i]);
        } else if (args[i] === '-c' || args[i] === '--count') {
            count = parseInt(args[++i]);
        } else if (args[i] === '--letters') letters = true;
        else if (args[i] === '--digits') digits = true;
        else if (args[i] === '--special') special = true;
        else if (args[i] === '--all') all = true;
        else if (args[i] === '--exclude-similar') exclSimilar = true;
        else if (args[i] === '--exclude-ambiguous') exclAmbiguous = true;
    }
    const useLetters = all || letters || config.useLetters;
    const useDigits = all || digits || config.useDigits;
    const useSpecial = all || special || config.useSpecial;
    const exSim = exclSimilar || config.excludeSimilar;
    const exAmb = exclAmbiguous || config.excludeAmbiguous;

    for (let i = 0; i < count; i++) {
        try {
            const pwd = generatePassword(length, useLetters, useDigits, useSpecial, exSim, exAmb);
            const ent = entropy(pwd);
            const years = crackTime(ent);
            console.log(`${i+1}) ${pwd}`);
            if (count === 1) {
                console.log(`Энтропия: ${ent.toFixed(1)} бит, время взлома: ~ ${years.toExponential(2)} лет`);
            }
        } catch (err) {
            console.error('Ошибка:', err.message);
        }
    }
}

main();
