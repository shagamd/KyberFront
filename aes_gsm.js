const crypto = require('crypto');

const IV_LENGTH = 16;
const TRANSFORMATION = 'aes-256-gcm';

function encrypt(json, bKey) {
    // const bKey = Buffer.from(llave, 'base64');
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(TRANSFORMATION, bKey, iv);
    let encrypted = cipher.update(json, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    const b64Cifrado = Buffer.concat([iv, Buffer.from(encrypted, 'hex'), tag]).toString('base64');
    return b64Cifrado;
}

function decrypt(b64Cifrado, bKey) {
    // const bKey = Buffer.from(llave, 'base64');
    const b64Buffer = Buffer.from(b64Cifrado, 'base64');
    const iv = b64Buffer.slice(0, IV_LENGTH);
    const tag = b64Buffer.slice(b64Buffer.length - 16);
    const encrypted = b64Buffer.slice(IV_LENGTH, b64Buffer.length - 16);
    const decipher = crypto.createDecipheriv(TRANSFORMATION, bKey, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');   
    return decrypted;
}

module.exports.encrypt = encrypt
module.exports.decrypt = decrypt