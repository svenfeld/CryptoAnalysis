package crypto.analysis;

import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.rules.CryptSLPredicate;
import sync.pds.solver.nodes.Node;

public class EnsuredCryptSLPredicate {

	private final CryptSLPredicate predicate;
	private Node<Statement, Val> location;

	public EnsuredCryptSLPredicate(CryptSLPredicate predicate, Node<Statement,Val> location) {
		this.predicate = predicate;
		this.location = location;
	}
	
	public CryptSLPredicate getPredicate(){
		return predicate;
	}
	
	public String toString() {
		return "Proved " + predicate.getPredName(); 
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((predicate == null) ? 0 : predicate.hashCode());
		result = prime * result + ((location == null) ? 0 : location.hashCode());
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
		EnsuredCryptSLPredicate other = (EnsuredCryptSLPredicate) obj;
		if (predicate == null) {
			if (other.predicate != null)
				return false;
		} else if (!predicate.equals(other.predicate))
			return false;
		if (location == null) {
			if (other.location != null)
				return false;
		} else if (!location.equals(other.location))
			return false;
		return true;
	}

}
