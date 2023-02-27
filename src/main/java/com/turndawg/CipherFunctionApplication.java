package com.turndawg;

import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CipherFunctionApplication {
//aws lambda create-function --function-name Encrypt --role arn:aws:iam::054904538216:role/lambda-ex --zip-file fileb://function-sample-aws-2.0.0.RELEASE-aws.jar  --handler org.springframework.cloud.function.adapter.aws.SpringBootStreamHandler --description "Cipher functionality to encrypt a specified string value." --runtime java8 --region us-west-2 --timeout 30 --memory-size 1024 --publish
//aws lambda create-function --function-name Decrypt --role arn:aws:iam::054904538216:role/lambda-ex --zip-file fileb://function-sample-aws-2.0.0.RELEASE-aws.jar  --handler org.springframework.cloud.function.adapter.aws.SpringBootStreamHandler --description "Cipher functionality to decrypt a specified string value." --runtime java8 --region us-west-2 --timeout 30 --memory-size 1024 --publish
		

/*
	 * You need this main method (empty) or explicit <start-class>example.FunctionConfiguration</start-class>
	 * in the POM to ensure boot plug-in makes the correct entry
	 */
	public static void main(String[] args) {
		// empty unless using Custom runtime at which point it should include
		SpringApplication.run(CipherFunctionApplication.class, args);
	}
	@Bean
	public CipherManager cipherUtil(@Value("${cipher.password}") String password,@Value("${cipher.salt}") String salt){
		return new CipherManager(password,salt);
	}

	@Bean
	public Function<String, String> encrypt(CipherManager cipher) {
		return value -> {
			try {
				return cipher.encrypt(value);
			} catch (Exception e) {
				throw new RuntimeException("Failed to encrypt value. Reason: " + e.getMessage());
			}
		};
	}
	@Bean
	public Function<String, String> decrypt(CipherManager cipher) {
		return value -> {
			try {
				return cipher.decrypt(value);
			} catch (Exception e) {
				throw new RuntimeException("Failed to decrypt value. Reason: " + e.getMessage());
			}
		};
	}
}
