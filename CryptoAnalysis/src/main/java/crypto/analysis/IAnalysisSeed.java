package crypto.analysis;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.Map.Entry;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import com.google.common.collect.Table.Cell;

import boomerang.ForwardQuery;
import boomerang.WeightedForwardQuery;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.constraints.ConstraintSolver;
import crypto.predicates.PredicateHandler;
import crypto.rules.CryptSLPredicate;
import soot.SootMethod;
import typestate.TransitionFunction;
import wpds.impl.Weight;

public abstract class IAnalysisSeed extends WeightedForwardQuery<TransitionFunction> {

	protected final CryptoScanner cryptoScanner;
	protected final PredicateHandler predicateHandler;
	private String objectId;
	protected final Set<RequiredCryptSLPredicate> ensuredPredicates = Sets.newHashSet();
	protected final Set<CryptSLPredicate> potentialPredicates = Sets.newHashSet();
	protected final Multimap<ForwardQuery,RequiredCryptSLPredicate> requiredPredicates = HashMultimap.create();
	protected final Multimap<Statement,RequiredCryptSLPredicate> ensuredPredicatesAtStatement = HashMultimap.create();
	protected boolean ensuresPredicates = false;
	protected Table<Statement, Val, ? extends Weight> analysisResults;
	
	public IAnalysisSeed(CryptoScanner scanner, Statement stmt, Val fact, TransitionFunction func){
		super(stmt,fact, func);
		this.cryptoScanner = scanner;
		this.predicateHandler = scanner.getPredicateHandler();
	}
	abstract void execute();

	public SootMethod getMethod(){
		return stmt().getMethod();
	}
	
	public String getObjectId() {
		if(objectId == null) {
			MessageDigest md;
			try {
				md = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
			this.objectId = new BigInteger(1, md.digest(this.toString().getBytes())).toString(16);
		}
		return this.objectId;
		
	}
	public boolean hasEnsuredPredicate(Statement stmt) {
		return ensuresPredicates && ensuredPredicatesAtStatement.keySet().contains(stmt);
	}

	public Collection<RequiredCryptSLPredicate> getPredicatesAtStatement(Statement s){
		if(ensuresPredicates) {
			return ensuredPredicatesAtStatement.get(s);
		}
		return Collections.emptySet();
	}
	public void addPotentiallyEnsuredPredicate(CryptSLPredicate potentialPredicate) {
		potentialPredicates.add(potentialPredicate);
	}
	
	public void addRequiredPredicate(ForwardQuery requiringObjectAllocation,
			RequiredCryptSLPredicate requiredCryptSLPredicate) {
		//CallTo, NeverTypeOf etc are not real required predicates
		if (ConstraintSolver.predefinedPreds.contains(requiredCryptSLPredicate.getPred().getPredName())) {
			return;
		}
		
		requiredPredicates.put(requiringObjectAllocation, requiredCryptSLPredicate);
	}
	
	public boolean checkPredicates() {
		if(ensuresPredicates) {
			return false;
		}
		boolean changed = false;
		Multimap<ForwardQuery, RequiredCryptSLPredicate> removablePredicate = HashMultimap.create();
		for(Entry<ForwardQuery, RequiredCryptSLPredicate> e : this.requiredPredicates.entries()) {
			System.out.println(e.getValue());
			if(e.getKey() instanceof IAnalysisSeed) {
				IAnalysisSeed iAnalysisSeed = (IAnalysisSeed) e.getKey();
				System.out.println(e.getKey());
				if(!e.getValue().getPred().isNegated() && iAnalysisSeed.hasEnsuredPredicate(e.getValue().getLocation())) {
					removablePredicate.put(e.getKey(), e.getValue());
					System.out.println("FOUND PREDICATE " + e.getValue());
					changed = true;
				}
			}
		}
		for(Entry<ForwardQuery, RequiredCryptSLPredicate> e : removablePredicate.entries()) {
			this.requiredPredicates.remove(e.getKey(), e.getValue());	
		}
		boolean allRequiredPredicatesFullFilled = true;
		for(Entry<ForwardQuery, RequiredCryptSLPredicate> e : this.requiredPredicates.entries()) {
			if(!e.getValue().getPred().isNegated()) {
				allRequiredPredicatesFullFilled = false;
			}
		}
		ensuresPredicates = allRequiredPredicatesFullFilled;
		
		//Does that makes sense?
		if(ensuresPredicates)
			addPotentialPredicates();
		return changed || ensuresPredicates;
	}
	
	public void addPotentialPredicates() {
		if(analysisResults == null)
			return;
		for(Cell<Statement, Val, ? extends Weight> c : analysisResults.cellSet()){
			for(CryptSLPredicate p : potentialPredicates) {
				ensuredPredicates.add(new RequiredCryptSLPredicate(p, c.getRowKey()));
				ensuredPredicatesAtStatement.put(c.getRowKey(), new RequiredCryptSLPredicate(p, c.getRowKey()));
			}
		}
	}
	
}
