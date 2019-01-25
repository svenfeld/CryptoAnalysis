package crypto.analysis;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import boomerang.WeightedForwardQuery;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.predicates.PredicateHandler;
import soot.SootMethod;
import typestate.TransitionFunction;

public abstract class IAnalysisSeed extends WeightedForwardQuery<TransitionFunction> {

	protected final CryptoScanner cryptoScanner;
	protected final PredicateHandler predicateHandler;
	private String objectId;
	protected final Set<RequiredCryptSLPredicate> ensuredPredicates = Sets.newHashSet();
	protected final Multimap<Statement,RequiredCryptSLPredicate> ensuredPredicatesAtStatement = HashMultimap.create();
	protected boolean ensuresPredicates = false;
	
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
	public boolean hasEnsuredPredicate(RequiredCryptSLPredicate value) {
		return ensuresPredicates && ensuredPredicates.contains(value);
	}

	public Collection<RequiredCryptSLPredicate> getPredicatesAtStatement(Statement s){
		if(ensuresPredicates) {
			return ensuredPredicatesAtStatement.get(s);
		}
		return Collections.emptySet();
	}
	
}
