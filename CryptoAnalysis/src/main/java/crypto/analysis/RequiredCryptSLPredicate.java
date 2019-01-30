package crypto.analysis;

import boomerang.jimple.Statement;
import crypto.rules.CryptSLPredicate;

public class RequiredCryptSLPredicate {

	private final CryptSLPredicate predicate;
	private final Statement stmt;
	private String predName;

	public RequiredCryptSLPredicate(CryptSLPredicate predicate, Statement stmt) {
		this.predicate = predicate;
		this.stmt = stmt;
		this.predName = predicate.getPredName();
		System.out.println(predName);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
//		result = prime * result + ((predicate == null) ? 0 : predicate.hashCode());
		result = prime * result + ((stmt == null) ? 0 : stmt.hashCode());
		result = prime * result + ((predName == null) ? 0 : predName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RequiredCryptSLPredicate other = (RequiredCryptSLPredicate) obj;
//		if (predicate == null) {
//			if (other.predicate != null)
//				return false;
//		} else if (!predicate.equals(other.predicate))
//			return false;
		if (stmt == null) {
			if (other.stmt != null)
				return false;
		} else if (!stmt.equals(other.stmt))
			return false;
		if (predName == null) {
			if (other.predName != null)
				return false;
		} else if (!predName.equals(other.predName))
			return false;
		return true;
	}

	public CryptSLPredicate getPred() {
		return predicate;
	}

	public Statement getLocation() {
		return stmt;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "misses " + predicate + " @ " + stmt.toString();
	}
}
