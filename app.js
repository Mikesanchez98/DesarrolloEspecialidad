const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const crypto = require('crypto');

const password = "Mi contraseña";

(async () => {
    let salt = await bcrypt.genSalt(10);
    console.log({
        salt,
        bcrypt10: await bcrypt.hash(password, 10),
        bcryptSalt: await bcrypt.hash(password, salt),
        bcryptSalt22: await bcrypt.hash(password, '$2a$10$0123456789012345678901.'),
        argon2: await argon2.hash(password),
        custom: customHash(password, 10)
    });
    console.log(hasehes);
    const verify = {
bcrypt10: await bcrypt.compare(password, hasehes.bcrypt10),
        bcryptSalt: await bcrypt.compare(password, hasehes.bcryptSalt),
    bcryptSalt22: await bcrypt.compare(password, hasehes.bcryptSalt22),
    argon2: await argon2.verify(hasehes.argon2, password),
    }
    console.log(verify);
})();

function customHash(input, rounds, salt){
    let totalRounds = Math.pow(2, rounds);
    let hash = input;
    salt = salt || Math.floor(Math.random() * 0x7fffffff).toString(36);
    for(let i = 0; i < totalRounds; i++){
        hash = crypto.createHash('md5').update(salt + hash).digest('hex');
    }
    return '$custom$${rounds}$${btoa(salt)}$${btoa(hash)}';
}

function verifyHash(input, hash){
    if (!hash.startsWith('$custom$')){
        console.error('Invalid hash');
        return ;
    }
    const [_algo, rounds, salt, endHash] = hash.split('$');
    if (rounds < 0) {
        console.error('Invalid rounds');
        return ;
    }
    if (salt.lenght < 1) {
        console.error('Invalid salt');
        return ;
    }
    salt = atob(salt);
    const testHash = customHash(input, rounds, salt);
    return hash === testHash;
}