package com.turndawg;

import java.io.Serializable;
import java.util.Objects;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.turndawg.AESUtil;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESUtilUnitTest {

    @Test
    public void givenString_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String input = "hello world";
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.getIvParameterSpec();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        String cipherText = AESUtil.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESUtil.decrypt(algorithm, cipherText, key, ivParameterSpec);

        // then
        Assertions.assertEquals(input, plainText);
    }

    @Test
    public void givenFile_whenEncrypt_thenSuccess()
        throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
        BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        SecretKey key = AESUtil.generateKey(128);
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = AESUtil.getIvParameterSpec();
        File inputFile = Paths.get("src/test/resources/helloworld.txt")
            .toFile();
        File encryptedFile = new File("helloworld.encrypted");
        File decryptedFile = new File("helloworld.decrypted");

        // when
        AESUtil.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        AESUtil.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);

        // then
        Assertions.assertTrue(filesCompareByLine(inputFile,decryptedFile) == -1L);
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
    }

    @Test
    public void givenObject_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IOException, BadPaddingException,
            ClassNotFoundException {
        // given
        Student student = new Student("Baeldung", 20);
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.getIvParameterSpec();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        SealedObject sealedObject = AESUtil.encryptObject(algorithm, student, key, ivParameterSpec);
        Student object = (Student) AESUtil.decryptObject(algorithm, sealedObject, key, ivParameterSpec);

        // then
        Assertions.assertEquals(student,object);
    }

    @Test
    public void givenPassword_whenEncrypt_thenSuccess()
            throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String plainText = "OK123456";
        String password = "crpytorpassword";
        String salt = "12345678";
        IvParameterSpec ivParameterSpec = AESUtil.getIvParameterSpec();
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);

        // when
        String cipherText = AESUtil.encryptPasswordBased(plainText, key);
        String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText, key);

        // then
        Assertions.assertEquals(plainText, decryptedCipherText);
    }

    /*
     * Compare textual content of 2 files. Compared line by line.
     * If all the lines are identical for both files, then we return -1L, but if
     * there's a discrepancy, we return the line number where the first mismatch is
     * found.
     * If the files are of different sizes but the smaller file matches the
     * corresponding lines of the larger file, then it returns the number of lines
     * of the smaller file.
     */
    public long filesCompareByLine(File f1, File f2) throws IOException {
        try (BufferedReader bf1 = Files.newBufferedReader(f1.toPath());
                BufferedReader bf2 = Files.newBufferedReader(f2.toPath())) {

            long lineNumber = 1;
            String line1 = "", line2 = "";
            while ((line1 = bf1.readLine()) != null) {
                line2 = bf2.readLine();
                if (line2 == null || !line1.equals(line2)) {
                    return lineNumber;
                }
                lineNumber++;
            }
            if (bf2.readLine() == null) {
                return -1;
            } else {
                return lineNumber;
            }
        }
    }
}

class Student implements Serializable {
    private String name;
    private int age;

    public Student(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        Student student = (Student) o;
        return age == student.age && Objects.equals(name, student.name);
    }
}
