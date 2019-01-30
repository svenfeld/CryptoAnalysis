package tests.pattern;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class KillFlowPatternTest extends UsagePatternTestingFramework{


	@Test
	public void UsagePatternTest18() throws GeneralSecurityException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		Assertions.extValue(0);
		final byte[] input = "input".getBytes("UTF-8");
		byte[] output = md.digest(input);
		Assertions.hasEnsuredPredicate(input);
		Assertions.hasEnsuredPredicate(output);
		output = null;
		Assertions.notHasEnsuredPredicate(output);
		md.reset();
		output = md.digest(input);
		Assertions.mustBeInAcceptingState(md);
		Assertions.hasEnsuredPredicate(input);
		Assertions.hasEnsuredPredicate(output);
	}

	@Test
	public void UsagePatternTest19() throws GeneralSecurityException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		Assertions.extValue(0);
		final byte[] input = "input".getBytes("UTF-8");
		final byte[] input2 = "input2".getBytes("UTF-8");
		byte[] output = md.digest(input);
		Assertions.hasEnsuredPredicate(input);
		Assertions.hasEnsuredPredicate(output);
		md.reset();
		md.update(input2);
		Assertions.mustNotBeInAcceptingState(md);
		Assertions.notHasEnsuredPredicate(input2);
		Assertions.hasEnsuredPredicate(output);
		md.digest();
	}
}
