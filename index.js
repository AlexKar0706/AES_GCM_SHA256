const AES_GCM_SHA256 = require('./Encryption_module/AES_GCM_SHA256');

let message = 'Text';
let privateKey = 'Very secret password';
let authentication_data = 'ip:192.168.1.1';
let AES_specification = 128; // 128/192/256

console.log('Is used AES_' + AES_specification + '_GCM_SHA256');
console.log('Initial message is: ' + message    );
let encrypted_message = AES_GCM_SHA256.encrypt(message, privateKey, authentication_data, AES_specification);
console.log('Encrypted message is: ' + encrypted_message);

let decrypted_message = AES_GCM_SHA256.decrypt(encrypted_message, privateKey, authentication_data, AES_specification);
console.log('Decrypted message is: ' + decrypted_message);