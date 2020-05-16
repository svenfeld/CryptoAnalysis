package crypto.analysis;

import java.util.Collection;

import boomerang.jimple.Statement;
import crypto.interfaces.ISLConstraintWithLocation;
import soot.SootMethod;

public interface ConstraintReporter {

	public void constraintViolated(ISLConstraintWithLocation con, Statement unit);
	
	void callToForbiddenMethod(ClassSpecification classSpecification, Statement callSite, SootMethod foundCall, Collection<SootMethod> convert);

	public void unevaluableConstraint(ISLConstraintWithLocation con, Statement unit);
}
