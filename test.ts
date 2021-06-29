// AES part

const aes_key_gen = AES_GenerateKey()
const aes_exported_key = AES_ExportKey(aes_key_gen)
const aes_imported_key = AES_ImportKey(aes_exported_key)

const to_be_encrypted = BytesToPromise([100, 200, 50, 1, 2, 3, 4])
to_be_encrypted.then((check) => { console.log(`AES checking before encryption: ${check}`) })

const aes_encrypted = AES_Encrypt(to_be_encrypted, aes_imported_key)
const aes_decrypted = AES_Decrypt(aes_encrypted, aes_imported_key)

aes_decrypted.then((decrypted) => { console.log(`AES checking after decryption: ${decrypted}`) })


// RSA part

const rsa_key_gen = RSA_GenerateKey()
const rsa_export_public_key = RSA_ExportPublicKey(rsa_key_gen)
const rsa_export_private_key = RSA_ExportPrivateKey(rsa_key_gen)

const rsa_import_public_key = RSA_ImportPublicKey(rsa_export_public_key);
const rsa_import_private_key = RSA_ImportPrivateKey(rsa_export_private_key);

const RSA_to_be_encrypted = BytesToPromise([9, 8, 7, 6, 5, 4, 3, 2, 1, 255])
RSA_to_be_encrypted.then((rsa_before) => { console.log(`RSA checking before encryption: ${rsa_before}`); })

const rsa_encrypted = RSA_Encrypt(RSA_to_be_encrypted, rsa_import_public_key)
const rsa_decrypted = RSA_Decrypt(rsa_encrypted, rsa_import_private_key)

rsa_decrypted.then((rsa_after) => { console.log(`RSA checking after decryption: ${rsa_after}`); })


function ForClarity() {
    // For string, simply use in built TextEncoder

    const txtenc = new TextEncoder()
    const txtdec = new TextDecoder()

    const string_encoded = BytesToPromise(txtenc.encode("Any string you wish. JSON stringify for JSON objects. If you're RSA there is a limit of 512 bytes!"))
    string_encoded.then((encoded_str) => {
        console.log("Checking string before encryption (array of bytes):");
        console.log(encoded_str);
    })

    const string_encrypted = AES_Encrypt(string_encoded, aes_imported_key)
    const string_decrypted = AES_Decrypt(string_encrypted, aes_imported_key)

    string_decrypted.then((string_check) => {
        console.log("Checking string after decryption (array of bytes, string):");
        console.log(string_check);
        console.log(txtdec.decode(string_check));
    })
}
setTimeout(ForClarity, 1000)