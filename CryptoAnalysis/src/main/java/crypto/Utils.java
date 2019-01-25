package crypto;

import java.util.Collection;
import java.util.Set;

import com.google.common.collect.Sets;

import crypto.rules.CryptSLMethod;
import crypto.rules.CryptSLRule;
import crypto.typestate.CryptSLMethodToSootMethod;
import soot.SootClass;
import soot.SootMethod;

public class Utils {

	public static SootClass getFullyQualifiedName(CryptSLRule r) {
		for(CryptSLMethod l : r.getUsagePattern().getInitialTransition().getLabel()) {
			for(SootMethod m : CryptSLMethodToSootMethod.v().convert(l)) {
				return m.getDeclaringClass();
			}
		}
		
		throw new RuntimeException("Could not get fully qualified class name for rule" + r);
	}

	public static Collection<String> toSubSignatures(Collection<SootMethod> methods) {
		Set<String> subSignatures = Sets.newHashSet();
		for(SootMethod m : methods){
			subSignatures.add(m.getName());
		}
		return subSignatures;
	}

}
