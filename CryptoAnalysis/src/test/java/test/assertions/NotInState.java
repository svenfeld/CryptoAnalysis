package test.assertions;

import boomerang.jimple.Val;
import crypto.typestate.ErrorStateNode;
import soot.Unit;
import test.Assertion;
import test.ComparableResult;
import typestate.finiteautomata.State;

public class NotInState implements Assertion, ComparableResult<State,Val> {

	private Unit unit;
	private Val accessGraph;
	private String state;
	private boolean satisfied = true;

	public NotInState(Unit unit, Val accessGraph, String state) {
		this.unit = unit;
		this.accessGraph = accessGraph;
		this.state = state;
	}

	public void computedResults(State s) {
		if (state.toString().equals(s.toString())) {
			satisfied = false;
		} 
	}

	public Unit getStmt() {
		return unit;
	}

	@Override
	public boolean isSatisfied() {
		return satisfied;
	}

	@Override
	public boolean isImprecise() {
		return false;
	}

	public Val getVal() {
		return accessGraph;
	}
	@Override
	public String toString() {
		return "["+getVal() + "@" + getStmt() + " must be in state "+ state+"]";
	}

}
