package com.turndawg;
import java.io.Serializable;
import java.util.Objects;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import com.turndawg.CipherManager;

public class CipherManagerTest {
    private static final String PASSWORD= "changeit";
    private String SALT="123";
    private CipherManager cipher;
    @BeforeEach
    public void beforeEach(){
        this.cipher = new CipherManager(PASSWORD,SALT);
    }
 
    @Test
    @EnabledIfEnvironmentVariable(named = "MAX_CIPHER_LENGTH", matches = "*")
    public void givenString_whenEncrypted_thenLengthIsLessThanEqualToMax(){
        String plainText = "hello world";
        String encryptedText = cipher.encrypt(plainText);
        //Assert the encrypted value is less than our configured max character length.
        Assertions.assertTrue(encryptedText.length() <= Integer.parseInt(System.getProperty("MAX_CIPHER_LENGTH")));
    }
    @Test
    public void givenString_whenEncrypted_thenSuccess(){
        String plainText = "hello world";
        String encryptedText = cipher.encrypt(plainText);
        //Assert that encrypted text is actually encrypted
        Assertions.assertNotEquals(plainText, encryptedText);
    }
    @Test
    public void givenEncryptedString_whenDecrypted_thenPlainTextIsRestored(){
        String plainText = "hello world";
        String encryptedText = cipher.encrypt(plainText);
        String decryptedText = cipher.decrypt(encryptedText);
        //Assert that encrypted text is actually encrypted
        Assertions.assertNotEquals(plainText, encryptedText);
        //Assert the encrypted 
        Assertions.assertEquals(plainText,decryptedText);
    }
}
