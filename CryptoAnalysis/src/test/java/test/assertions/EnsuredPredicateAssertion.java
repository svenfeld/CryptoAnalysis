package test.assertions;

import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.analysis.EnsuredCryptSLPredicate;
import crypto.analysis.RequiredCryptSLPredicate;
import soot.jimple.Stmt;
import test.Assertion;

public abstract class EnsuredPredicateAssertion implements Assertion {

	protected Statement stmt;
	protected Val val;
	protected boolean imprecise = false;
	protected boolean satisfied = false;

	public EnsuredPredicateAssertion(Statement stmt, Val val) {
		this.stmt = stmt;
		this.val = val;
	}
	
	public Val getAccessGraph() {
		return val;
	}


	public Statement getStmt() {
		return stmt;
	}

	public abstract void reported(Val value, RequiredCryptSLPredicate pred);

	@Override
	public String toString() {
		return "Did not expect a predicate for "+ val +" @ " + stmt;  
	}
}
