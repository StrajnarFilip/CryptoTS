"use strict";
// AES part
var aes_key_gen = AES_GenerateKey();
var aes_exported_key = AES_ExportKey(aes_key_gen);
var aes_imported_key = AES_ImportKey(aes_exported_key);
var to_be_encrypted = BytesToPromise([100, 200, 50, 1, 2, 3, 4]);
to_be_encrypted.then(function (check) { console.log("AES checking before encryption: " + check); });
var aes_encrypted = AES_Encrypt(to_be_encrypted, aes_imported_key);
var aes_decrypted = AES_Decrypt(aes_encrypted, aes_imported_key);
aes_decrypted.then(function (decrypted) { console.log("AES checking after decryption: " + decrypted); });
// RSA part
var rsa_key_gen = RSA_GenerateKey();
var rsa_export_public_key = RSA_ExportPublicKey(rsa_key_gen);
var rsa_export_private_key = RSA_ExportPrivateKey(rsa_key_gen);
var rsa_import_public_key = RSA_ImportPublicKey(rsa_export_public_key);
var rsa_import_private_key = RSA_ImportPrivateKey(rsa_export_private_key);
var RSA_to_be_encrypted = BytesToPromise([9, 8, 7, 6, 5, 4, 3, 2, 1, 255]);
RSA_to_be_encrypted.then(function (rsa_before) { console.log("RSA checking before encryption: " + rsa_before); });
var rsa_encrypted = RSA_Encrypt(RSA_to_be_encrypted, rsa_import_public_key);
var rsa_decrypted = RSA_Decrypt(rsa_encrypted, rsa_import_private_key);
rsa_decrypted.then(function (rsa_after) { console.log("RSA checking after decryption: " + rsa_after); });
function ForClarity() {
    // For string, simply use in built TextEncoder
    var txtenc = new TextEncoder();
    var txtdec = new TextDecoder();
    var string_encoded = BytesToPromise(txtenc.encode("Any string you wish. JSON stringify for JSON objects. If you're RSA there is a limit of 512 bytes!"));
    string_encoded.then(function (encoded_str) {
        console.log("Checking string before encryption (array of bytes):");
        console.log(encoded_str);
    });
    var string_encrypted = AES_Encrypt(string_encoded, aes_imported_key);
    var string_decrypted = AES_Decrypt(string_encrypted, aes_imported_key);
    string_decrypted.then(function (string_check) {
        console.log("Checking string after decryption (array of bytes, string):");
        console.log(string_check);
        console.log(txtdec.decode(string_check));
    });
}
setTimeout(ForClarity, 1000);
