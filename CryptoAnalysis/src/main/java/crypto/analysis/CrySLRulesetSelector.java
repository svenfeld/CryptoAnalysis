package crypto.analysis;

import java.io.File;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.collect.Lists;
import crypto.exceptions.CryptoAnalysisException;
import de.darmstadt.tu.crossing.handler.Parser;
import de.darmstadt.tu.crossing.rules.CrySLRule;
import de.darmstadt.tu.crossing.rules.CrySLRuleReader;

public class CrySLRulesetSelector {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CrySLRulesetSelector.class);
	
	public static enum RuleFormat {
		SOURCE() {
			public String toString() {
				return Parser.cryslFileEnding;
			}
		},
	}

	public static enum Ruleset {
		JavaCryptographicArchitecture, BouncyCastle, Tink
	}

	public static List<CrySLRule> makeFromRuleset(String rulesBasePath, RuleFormat ruleFormat, Ruleset... set) {
		List<CrySLRule> rules = Lists.newArrayList();
		for (Ruleset s : set) {
			rules.addAll(getRulesset(rulesBasePath, ruleFormat, s));
		}
		if (rules.isEmpty()) {
			LOGGER.info("No CrySL rules found for rulesset " + set);
		}
		return rules;
	}

	/**
	 * Computes the ruleset from a string. The sting
	 * 
	 * @param rulesetString
	 * @return
	 * @throws CryptoAnalysisException 
	 */
	public static List<CrySLRule> makeFromRulesetString(String rulesBasePath, RuleFormat ruleFormat,
			String rulesetString) throws CryptoAnalysisException {
		String[] set = rulesetString.split(",");
		List<Ruleset> ruleset = Lists.newArrayList();
		for (String s : set) {
			if (s.equalsIgnoreCase(Ruleset.JavaCryptographicArchitecture.name())) {
				ruleset.add(Ruleset.JavaCryptographicArchitecture);
			}
			if (s.equalsIgnoreCase(Ruleset.BouncyCastle.name())) {
				ruleset.add(Ruleset.BouncyCastle);
			}
			if (s.equalsIgnoreCase(Ruleset.Tink.name())) {
				ruleset.add(Ruleset.Tink);
			}
		}
		if (ruleset.isEmpty()) {
			throw new CryptoAnalysisException("Could not parse " + rulesetString + ". Was not able to find rulesets.");
		}
		return makeFromRuleset(rulesBasePath, ruleFormat, ruleset.toArray(new Ruleset[ruleset.size()]));
	}

	private static List<CrySLRule> getRulesset(String rulesBasePath, RuleFormat ruleFormat, Ruleset s) {
		List<CrySLRule> rules = Lists.newArrayList();
		File[] listFiles = new File(rulesBasePath + s + "/").listFiles();
		for (File file : listFiles) {
			CrySLRule rule = CrySLRuleReader.readFromSourceFile(file);
			if(rule != null) {
				rules.add(rule);
			}
		}
		return rules;
	}

	public static CrySLRule makeSingleRule(String rulesBasePath, RuleFormat ruleFormat, Ruleset ruleset,
			String rulename) {
		File file = new File(rulesBasePath + "/" + ruleset + "/" + rulename + RuleFormat.SOURCE);
		if (file.exists()) {
			CrySLRule rule = CrySLRuleReader.readFromSourceFile(file);
			return rule;
		}
		return null;
	}

	public static List<CrySLRule> makeFromPath(File resourcesPath, RuleFormat ruleFormat) throws CryptoAnalysisException {
		if (!resourcesPath.isDirectory())
			throw new CryptoAnalysisException("The specified path is not a directory " + resourcesPath);
		List<CrySLRule> rules = Lists.newArrayList();
		File[] listFiles = resourcesPath.listFiles();
		for (File file : listFiles) {
			CrySLRule rule = CrySLRuleReader.readFromSourceFile(file);
			if(rule != null) {
				rules.add(rule);
			}
		}
		if (rules.isEmpty()) {
			throw new CryptoAnalysisException("No CrySL rules found in " + resourcesPath);
		}
		return rules;
	}
}
