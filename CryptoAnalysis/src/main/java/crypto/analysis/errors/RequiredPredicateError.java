package crypto.analysis.errors;

import boomerang.jimple.Statement;
import crypto.extractparameter.CallSiteWithExtractedValue;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.rules.CryptSLPredicate;
import crypto.rules.CryptSLRule;

public class RequiredPredicateError extends AbstractError{

	private CryptSLPredicate contradictedPredicate;
	private CallSiteWithParamIndex extractedValues;

	public RequiredPredicateError(CryptSLPredicate contradictedPredicate, Statement location, CryptSLRule rule, CallSiteWithParamIndex callSite) {
		super(location, rule);
		this.contradictedPredicate = contradictedPredicate;
		this.extractedValues = callSite;
	}

	public CryptSLPredicate getContradictedPredicate() {
		return contradictedPredicate;
	}
	
	public CallSiteWithParamIndex getExtractedValues() {
		return extractedValues;
	}
	
	public void accept(ErrorVisitor visitor){
		visitor.visit(this);
	}


	@Override
	public String toErrorMarkerString() {
		String msg = extractedValues.toString();
		msg += " was not properly generated as ";
		String predicateName = getContradictedPredicate().getPredName();
		String[] parts = predicateName.split("(?=[A-Z])");
		msg += parts[0];
		for(int i=1; i<parts.length; i++)
			msg += " " + parts[i];
		return msg;
	}
}
