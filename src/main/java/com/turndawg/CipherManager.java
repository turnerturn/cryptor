package com.turndawg;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CipherManager{

    private  final String password;
    private  final String salt;
    public CipherManager(final String password,final String salt) {
        this.password = password;
        this.salt = salt;
    }
    public String encrypt(String value) throws RuntimeException{
        try{

            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
            return AESUtil.encryptPasswordBased(value, key);
        }catch(Exception e){
            throw new RuntimeException("Failed to encrypt value.  Reason: "+ e.getMessage());
        }
    }
    public String decrypt(String value) throws RuntimeException{
       
        try{
            SecretKey key = AESUtil.getKeyFromPassword(password, salt);
            return AESUtil.decryptPasswordBased(value, key);
        }catch(Exception e){
            throw new RuntimeException("Failed to decrypt value.  Reason: "+ e.getMessage());
        }
    }
}