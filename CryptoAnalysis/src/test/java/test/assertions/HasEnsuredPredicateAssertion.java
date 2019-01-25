package test.assertions;

import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.analysis.RequiredCryptSLPredicate;

public class HasEnsuredPredicateAssertion extends  EnsuredPredicateAssertion{

	public HasEnsuredPredicateAssertion(Statement stmt, Val val) {
		super(stmt, val);
	}

	@Override
	public boolean isSatisfied() {
		return satisfied;
	}

	@Override
	public boolean isImprecise() {
		return false;
	}


	public Statement getStmt() {
		return stmt;
	}

	public void reported(Val seed, RequiredCryptSLPredicate pred) {
		if(seed.equals(val))
			satisfied = true;
	}

	@Override
	public String toString() {
		return "Expected a predicate for "+ val +" @ " + stmt;  
	}

}
