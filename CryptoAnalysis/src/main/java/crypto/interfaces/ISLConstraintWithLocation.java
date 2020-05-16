package crypto.interfaces;

import java.util.Set;

import boomerang.jimple.Statement;

public interface ISLConstraintWithLocation extends de.darmstadt.tu.crossing.interfaces.ISLConstraint {

	public void setLocation(Statement location);

	public Statement getLocation();

}
