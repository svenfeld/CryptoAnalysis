package crypto.interfaces;

import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import com.google.common.collect.Sets;
import de.darmstadt.tu.crossing.interfaces.ISLConstraint;
import de.darmstadt.tu.crossing.rules.CrySLForbiddenMethod;
import de.darmstadt.tu.crossing.rules.CrySLPredicate;
import de.darmstadt.tu.crossing.rules.CrySLRule;
import de.darmstadt.tu.crossing.rules.StateMachineGraph;
import soot.SootMethod;

public class CrySLRuleSAST extends CrySLRule {
	
	private static final long serialVersionUID = 334541796717647112L;

	public CrySLRuleSAST(String _className, List<Entry<String, String>> defObjects, List<CrySLForbiddenMethod> _forbiddenMethods, StateMachineGraph _usagePattern, List<ISLConstraint> _constraints, List<CrySLPredicate> _predicates) {
		super(_className, defObjects, _forbiddenMethods, _usagePattern, _constraints, _predicates);
	}

	public static Collection<String> toSubSignatures(Collection<SootMethod> methods) {
		Set<String> subSignatures = Sets.newHashSet();
		for(SootMethod m : methods){
			subSignatures.add(m.getName());
		}
		return subSignatures;
	}

}
