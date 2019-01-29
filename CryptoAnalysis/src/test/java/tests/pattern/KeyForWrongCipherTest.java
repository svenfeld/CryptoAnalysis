package tests.pattern;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class KeyForWrongCipherTest extends UsagePatternTestingFramework{

	@Test
	public void UsagePatternTestInter4() throws GeneralSecurityException {
		SecretKey key = generateKey();
		Assertions.hasEnsuredPredicate(key);
		wrongRebuild(key);
	}

	private SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		Assertions.extValue(0);
		keygen.init(128);
		Assertions.extValue(0);
		SecretKey key = keygen.generateKey();

		Assertions.mustBeInAcceptingState(keygen);
		return key;
	}
	
	private void wrongRebuild(SecretKey key) throws GeneralSecurityException {
		SecretKey tmpKey = new SecretKeySpec(key.getEncoded(), "DES");
		Assertions.hasEnsuredPredicate(tmpKey);
		encryptWrong(tmpKey);
	}

	private void encryptWrong(SecretKey key) throws GeneralSecurityException {
		Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Assertions.extValue(0);
		cCipher.init(Cipher.ENCRYPT_MODE, key);

		Assertions.extValue(0);
		byte[] encText = cCipher.doFinal("".getBytes());
		//TODO: correct would be
//		Assertions.notHasEnsuredPredicate(encText);
		Assertions.hasEnsuredPredicate(encText);
		Assertions.mustBeInAcceptingState(cCipher);
		cCipher.getIV();
	}
}
