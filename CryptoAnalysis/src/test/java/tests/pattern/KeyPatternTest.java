package tests.pattern;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class KeyPatternTest extends UsagePatternTestingFramework {
	@Test
	public void clearPasswordPredicateTest() throws NoSuchAlgorithmException, GeneralSecurityException {
		Encryption encryption = new Encryption();
		encryption.encryptData(new  byte[] {}, "Test");
	}
	
	public static class Encryption {
	      byte[] salt = {15, -12, 94, 0, 12, 3, -65, 73, -1, -84, -35};
	    
	      private SecretKey generateKey(String password) throws NoSuchAlgorithmException, GeneralSecurityException {
	 		  PBEKeySpec pBEKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);

			  SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithSHA256");
			  Assertions.notHasEnsuredPredicate(pBEKeySpec);
			  SecretKey generateSecret = secretKeyFactory.generateSecret(pBEKeySpec);
			  Assertions.notHasEnsuredPredicate(generateSecret);
			  byte[] keyMaterial = generateSecret.getEncoded();
			  Assertions.notHasEnsuredPredicate(keyMaterial);
			  SecretKey encryptionKey = new SecretKeySpec(keyMaterial, "AES");
			  //pBEKeySpec.clearPassword();
			  Assertions.notHasEnsuredPredicate(encryptionKey);
			  return encryptionKey;
	      }
	    
	    private byte[] encrypt(byte[] plainText, SecretKey encryptionKey) throws GeneralSecurityException {
	          Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	          cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
	          return cipher.doFinal(plainText);
	      }
	    
	      public byte[] encryptData(byte[] plainText, String password) throws NoSuchAlgorithmException, GeneralSecurityException {
	          return encrypt(plainText, generateKey(password));
	      }
	}
	
	@Test
	public void UsagePatternTest1Simple() throws GeneralSecurityException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		Assertions.extValue(0);
		keygen.init(128);
		Assertions.extValue(0);
		SecretKey key = keygen.generateKey();
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keygen);
		
	}
	@Test
	public void incorretKeyGeneratorUseLeadingToGenKey() throws GeneralSecurityException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		Assertions.extValue(0);
		keygen.init(1228);
		Assertions.extValue(0);
		SecretKey key = keygen.generateKey();
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keygen);
	}
	

	@Test
	public void UsagePatternTest21a() throws GeneralSecurityException, UnsupportedEncodingException {
		String input = "TESTITESTiTEsTI";

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		Assertions.extValue(0);
		keyGen.initialize(2048);
		KeyPair kp = keyGen.generateKeyPair();
		Assertions.mustBeInAcceptingState(keyGen);
		Assertions.hasEnsuredPredicate(kp);

		final PrivateKey privKey = kp.getPrivate();
		Assertions.hasEnsuredPredicate(privKey);
		String algorithm = "SHA256withDSA";
		if (Math.random() % 2 == 0) {
			algorithm = "SHA256withECDSA";
		}
		Signature sign = Signature.getInstance(algorithm);
		Assertions.extValue(0);

		sign.initSign(privKey);
		sign.update(input.getBytes("UTF-8"));
		byte[] signature = sign.sign();
		Assertions.mustBeInAcceptingState(sign);
		Assertions.hasEnsuredPredicate(signature);

	}
	
	@Test
	public void UsagePatternTest21() throws GeneralSecurityException, UnsupportedEncodingException {
		String input = "TESTITESTiTEsTI";

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		Assertions.extValue(0);
		keyGen.initialize(2048);
		KeyPair kp = keyGen.generateKeyPair();
		Assertions.mustBeInAcceptingState(keyGen);
		Assertions.hasEnsuredPredicate(kp);

		final PrivateKey privKey = kp.getPrivate();
		Assertions.hasEnsuredPredicate(privKey);
		Signature sign = Signature.getInstance("SHA256withDSA");
		Assertions.extValue(0);

		sign.initSign(privKey);
		sign.update(input.getBytes("UTF-8"));
		byte[] signature = sign.sign();
		Assertions.mustBeInAcceptingState(sign);
		Assertions.hasEnsuredPredicate(signature);

	}


	@Test
	public void UsagePatternTest22() throws GeneralSecurityException, UnsupportedEncodingException {
		String input = "TESTITESTiTEsTI";

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		Assertions.extValue(0);
		keyGen.initialize(2048);
		KeyPair kp = keyGen.generateKeyPair();
		Assertions.mustBeInAcceptingState(keyGen);
		Assertions.hasEnsuredPredicate(kp);

		final PrivateKey privKey = kp.getPrivate();
		Assertions.mustBeInAcceptingState(kp);
		Assertions.hasEnsuredPredicate(privKey);
		Signature sign = Signature.getInstance("SHA256withDSA");
		Assertions.extValue(0);

		sign.initSign(privKey);
		sign.update(input.getBytes("UTF-8"));
		byte[] signature = sign.sign();
		Assertions.mustBeInAcceptingState(sign);
		Assertions.hasEnsuredPredicate(signature);

		final PublicKey pubKey = kp.getPublic();
		Assertions.mustBeInAcceptingState(kp);
		Assertions.hasEnsuredPredicate(pubKey);

		Signature ver = Signature.getInstance("SHA256withDSA");
		Assertions.extValue(0);
		//		
		ver.initVerify(pubKey);
		ver.update(input.getBytes("UTF-8"));
		ver.verify(signature);
		Assertions.mustBeInAcceptingState(ver);
	}

	
	@Test
	public void clearPasswordPredicateTest2() throws NoSuchAlgorithmException, GeneralSecurityException {
		  String password = "test";
		  byte[] salt = {15, -12, 94, 0, 12, 3, -65, 73, -1, -84, -35};
		  PBEKeySpec pBEKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);

		  SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithSHA256");
		  Assertions.extValue(0);
		  Assertions.notHasEnsuredPredicate(pBEKeySpec);
		  SecretKey generateSecret = secretKeyFactory.generateSecret(pBEKeySpec);
		  Assertions.notHasEnsuredPredicate(generateSecret);
		  byte[] keyMaterial = generateSecret.getEncoded();
		  Assertions.notHasEnsuredPredicate(keyMaterial);
	}
}
