package crypto.analysis.errors;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.base.Joiner;
import com.google.common.base.Optional;

import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.analysis.IAnalysisSeed;
import crypto.rules.CryptSLRule;
import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

public class IncompleteOperationError extends ErrorWithObjectAllocation{

	private Val errorVariable;
	private Collection<SootMethod> expectedMethodCalls;

	public IncompleteOperationError(Statement errorLocation,
			Val errorVariable, CryptSLRule rule, IAnalysisSeed objectLocation, Collection<SootMethod> expectedMethodsToBeCalled) {
		super(errorLocation, rule, objectLocation);
		this.errorVariable = errorVariable;
		this.expectedMethodCalls = expectedMethodsToBeCalled;	
	}

	public Val getErrorVariable() {
		return errorVariable;
	}
	
	public Collection<SootMethod> getExpectedMethodCalls() {
		return expectedMethodCalls;
	}
	
	public void accept(ErrorVisitor visitor){
		visitor.visit(this);
	}

	@Override
	public String toErrorMarkerString() {
		Collection<SootMethod> expectedCalls = getExpectedMethodCalls();
		final StringBuilder msg = new StringBuilder();
		msg.append("Operation");
		msg.append(getObjectType());
		msg.append(" object not completed. Expected call to ");
		final Set<String> altMethods = new HashSet<>();
		for (final SootMethod expectedCall : expectedCalls) {
			if (stmtInvokesExpectedCallName(expectedCall.getName())){
				altMethods.add(expectedCall.getSignature().replace("<", "").replace(">", ""));
			} else {
				altMethods.add(expectedCall.getName().replace("<", "").replace(">", ""));
			}
		}
		msg.append(Joiner.on(", ").join(altMethods));
		return msg.toString();
	}

	/**
	 * This method checks whether the statement at which the error is located already calls a method with the same name.
	 * This occurs when a call to the method with the correct name, but wrong signature is invoked.
	 */
	private boolean stmtInvokesExpectedCallName(String expectedCallName){
		Statement errorLocation = getErrorLocation();
		if (errorLocation.isCallsite()){
			Optional<Stmt> stmtOptional = errorLocation.getUnit();
			if (stmtOptional.isPresent()){
				Stmt stmt = stmtOptional.get();
				if (stmt.containsInvokeExpr()){
					InvokeExpr call = stmt.getInvokeExpr();
					SootMethod calledMethod = call.getMethod();
					if (calledMethod.getName().equals(expectedCallName)){
						return true;
					}
				}
			}
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((expectedMethodCalls == null) ? 0 :expectedMethodCallsHashCode(expectedMethodCalls));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		IncompleteOperationError other = (IncompleteOperationError) obj;
		if (expectedMethodCalls == null) {
			if (other.expectedMethodCalls != null)
				return false;
		} else if (expectedMethodCallsHashCode(expectedMethodCalls) != (expectedMethodCallsHashCode(other.expectedMethodCalls)))
			return false;
		
		return true;
	}
	
	private int expectedMethodCallsHashCode(Collection<SootMethod> expectedMethodCalls) {
		final int prime = 31;
		int result = 1;
		
		List<SootMethod> expectedMethodCallsList = new ArrayList<SootMethod>(expectedMethodCalls);
		Collections.sort(expectedMethodCallsList, new Comparator<SootMethod>() {
			public int compare(SootMethod s1, SootMethod s2) {
				return s1.getSignature().toString().compareToIgnoreCase(s2.getSignature().toString());
			}
		});

		for (SootMethod method : expectedMethodCallsList) {
			result = prime * result + ((method == null) ? 0 : method.getSignature().toString().hashCode());
		}
		return result;
	}
	
	
}
