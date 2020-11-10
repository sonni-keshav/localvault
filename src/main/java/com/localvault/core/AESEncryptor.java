package com.localvault.core;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESEncryptor implements Encryptor {

    // Salting here only to get a specific key length
    private static final String STATIC_SALT = "AES_Static_Salt";
    private static final String KEY_GEN_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int SALT_ITERATIONS = 65536;
    private static final int AES_KEY_LENGTH = 256;

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private enum CipherMode {
        ENCRYPT, DECRYPT
    }

    @Override
    public byte[] encrypt(String data, String password)
            throws EncryptionException, CipherInitException {
        Cipher cipher = createAESCipher(password, CipherMode.ENCRYPT);

        try {
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            throw new EncryptionException("Failed to encrypt data with AES");
        }
    }

    @Override
    public String decrypt(byte[] data, String password)
            throws DecryptionException, CipherInitException {
        Cipher cipher = createAESCipher(password, CipherMode.DECRYPT);

        try {
            return new String(cipher.doFinal(data));
        } catch (Exception e) {
            throw new DecryptionException("Failed to decrypt data with AES");
        }
    }

    private Cipher createAESCipher(String password, CipherMode mode) throws CipherInitException {
        try {
            SecretKeySpec key = createKeyFromPassword(password);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(getCipherModeFlag(mode), key);
            return cipher;
        } catch (InvalidKeySpecException e) {
            throw new CipherInitException("Failed to create AES key from password");
        } catch (Exception e) {
            throw new CipherInitException("Failed to init AES cipher");
        }
    }

    private SecretKeySpec createKeyFromPassword(String password) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        var spec = new PBEKeySpec(password.toCharArray(), STATIC_SALT.getBytes(),
                SALT_ITERATIONS, AES_KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
        byte[] key = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, AES_ALGORITHM);
    }

    private int getCipherModeFlag(CipherMode mode) {
        switch (mode) {
            case ENCRYPT:
                return Cipher.ENCRYPT_MODE;
            case DECRYPT:
            default:
                return Cipher.DECRYPT_MODE;
        }
    }
}
