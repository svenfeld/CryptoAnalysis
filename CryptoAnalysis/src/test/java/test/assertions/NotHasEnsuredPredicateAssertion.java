package test.assertions;

import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.analysis.RequiredCryptSLPredicate;

public class NotHasEnsuredPredicateAssertion extends EnsuredPredicateAssertion{


	public NotHasEnsuredPredicateAssertion(Statement stmt, Val val) {
		super(stmt, val);
	}

	@Override
	public boolean isSatisfied() {
		return true;
	}

	@Override
	public boolean isImprecise() {
		return imprecise;
	}


	public void reported(Val value, RequiredCryptSLPredicate pred) {
		if(value.equals(val)){
			imprecise = true;
		}
	}

	@Override
	public String toString() {
		return "Did not expect a predicate for "+ val +" @ " + stmt;  
	}

}
