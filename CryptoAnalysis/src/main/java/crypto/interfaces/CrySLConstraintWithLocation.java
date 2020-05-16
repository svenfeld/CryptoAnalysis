package crypto.interfaces;

import boomerang.jimple.Statement;
import de.darmstadt.tu.crossing.interfaces.ISLConstraint;
import de.darmstadt.tu.crossing.rules.CrySLConstraint;

public class CrySLConstraintWithLocation extends CrySLConstraint implements ISLConstraintWithLocation {

	private static final long serialVersionUID = -3810373066379526741L;

	public CrySLConstraintWithLocation(ISLConstraint l, ISLConstraint r, LogOps op) {
		super(l, r, op);
	}

	private Statement location;
	
	public void setLocation(Statement location) {
		this.location = location;
	}

	public Statement getLocation() {
		return location;
	}

}
