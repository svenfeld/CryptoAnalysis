package crypto.interfaces;

import de.darmstadt.tu.crossing.interfaces.ISLConstraint;

public class CrySLLiteralWithLocation extends CrySLConstraintWithLocation{

	private static final long serialVersionUID = 7231255104424913244L;

	public CrySLLiteralWithLocation(ISLConstraint l, ISLConstraint r, LogOps op) {
		super(l, r, op);
	}

	
}
