package com.localvault.core.test;

import com.localvault.core.AESEncryptor;
import com.localvault.core.Encryptor;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestAESEncryptor {

    @Test
    public void encryptAndDecryptSymmetric() throws Exception {
        Encryptor crypt = new AESEncryptor();
        String password = "password";
        String data = "Secret data";

        byte[] encrypted = crypt.encrypt(data, password);
        String decrypted = crypt.decrypt(encrypted, password);
        assertEquals(data, decrypted);
    }


}
