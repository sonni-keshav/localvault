package com.localvault.core;

public interface Encryptor {

    byte[] encrypt(String data, String password) throws EncryptionException, CipherInitException;

    String decrypt(byte [] data, String password) throws DecryptionException, CipherInitException;

    // Exceptions

    class CipherInitException extends Exception {
        public CipherInitException(String message) { super(message); }
    }

    class EncryptionException extends  Exception {
        public EncryptionException(String message) { super(message); }
    }

    class DecryptionException extends  Exception {
        public DecryptionException(String message) { super(message); }
    }
}
