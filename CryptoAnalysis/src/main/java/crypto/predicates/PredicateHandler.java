package crypto.predicates;

import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.base.Optional;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import com.google.common.collect.Table.Cell;
import com.google.inject.internal.util.Lists;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.ForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.results.AbstractBoomerangResults;
import boomerang.results.BackwardBoomerangResults;
import boomerang.results.ForwardBoomerangResults;
import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.analysis.ClassSpecification;
import crypto.analysis.CryptoScanner;
import crypto.analysis.EnsuredCryptSLPredicate;
import crypto.analysis.IAnalysisSeed;
import crypto.analysis.RequiredCryptSLPredicate;
import crypto.analysis.ResultsHandler;
import crypto.analysis.errors.PredicateContradictionError;
import crypto.analysis.errors.RequiredPredicateError;
import crypto.boomerang.CogniCryptBoomerangOptions;
import crypto.constraints.ConstraintSolver;
import crypto.constraints.ConstraintSolver.EvaluableConstraint;
import crypto.extractparameter.CallSiteWithExtractedValue;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.interfaces.ISLConstraint;
import crypto.rules.CryptSLPredicate;
import crypto.rules.CryptSLRule;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import typestate.TransitionFunction;
import wpds.impl.Weight.NoWeight;

public class PredicateHandler {

	private final Table<Statement, Val, Set<EnsuredCryptSLPredicate>> existingPredicates = HashBasedTable.create();
	private final Table<Statement, IAnalysisSeed, Set<EnsuredCryptSLPredicate>> existingPredicatesObjectBased = HashBasedTable.create();
	private final Table<Statement, IAnalysisSeed, Set<CryptSLPredicate>> expectedPredicateObjectBased = HashBasedTable.create();
	private final Table<IAnalysisSeed, IAnalysisSeed, Set<RequiredCryptSLPredicate>> requiredPredicates = HashBasedTable.create();
	private final CryptoScanner cryptoScanner;
	
	public PredicateHandler(CryptoScanner cryptoScanner) {
		this.cryptoScanner = cryptoScanner;
	}

//	public boolean addPotentialPredicate(IAnalysisSeed seedObj, Statement statement, Val variable, EnsuredCryptSLPredicate ensPred) {
//		Set<EnsuredCryptSLPredicate> set = getExistingPredicates(statement, variable);
//		boolean added = set.add(ensPred);
//		assert existingPredicates.get(statement, variable).contains(ensPred);
//		if (added) {
//			onPredicateAdded(seedObj, statement, variable, ensPred);
//		}
//		cryptoScanner.getAnalysisListener().onSecureObjectFound(seedObj);
//		Set<EnsuredCryptSLPredicate> predsObjBased = existingPredicatesObjectBased.get(statement, seedObj);
//		if (predsObjBased == null)
//			predsObjBased = Sets.newHashSet();
//		predsObjBased.add(ensPred);
//		existingPredicatesObjectBased.put(statement, seedObj, predsObjBased);
//		return added;
//	}
	
	/**
	 * @return the existingPredicates
	 */
	public Set<EnsuredCryptSLPredicate> getExistingPredicates(Statement stmt, Val seed) {
		Set<EnsuredCryptSLPredicate> set = existingPredicates.get(stmt, seed);
		if (set == null) {
			set = Sets.newHashSet();
			existingPredicates.put(stmt, seed, set);
		}
		return set;
	}
	

	public void checkPredicates() {
//		checkAllConstraints();
	}

//	private void checkMissingRequiredPredicates() {
//		for (AnalysisSeedWithSpecification seed : cryptoScanner.getAnalysisSeeds()) {
//			Set<RequiredCryptSLPredicate> missingPredicates = seed.getMissingPredicates();
//			for(RequiredCryptSLPredicate pred : missingPredicates){
//				CryptSLRule rule = seed.getSpec().getRule();
//				if (!rule.getPredicates().contains(pred.getPred())){
//					for(CallSiteWithParamIndex v : seed.getParameterAnalysis().getCollectedValues().keySet()){
//						if(pred.getPred().getInvolvedVarNames().contains(v.getVarName()) && v.stmt().equals(pred.getLocation())){
//							cryptoScanner.getAnalysisListener().reportError(seed, new RequiredPredicateError(pred.getPred(), pred.getLocation(), seed.getSpec().getRule(), new CallSiteWithExtractedValue(v, null)));
//						}
//					}
//				}
//			}
//		}	
//	}

//	private void checkForContradictions() {
//		Set<Entry<CryptSLPredicate, CryptSLPredicate>> contradictionPairs = new HashSet<Entry<CryptSLPredicate, CryptSLPredicate>>();
//		for(ClassSpecification c : cryptoScanner.getClassSpecifictions()) {
//			CryptSLRule rule = c.getRule();
//			for (ISLConstraint cons : rule.getConstraints()) {
//				if (cons instanceof CryptSLPredicate && ((CryptSLPredicate) cons).isNegated()) {
//					contradictionPairs.add(new SimpleEntry<CryptSLPredicate, CryptSLPredicate>(rule.getPredicates().get(0), ((CryptSLPredicate) cons).setNegated(false)));
//				}
//			}
//		}
//		for (Statement generatingPredicateStmt : expectedPredicateObjectBased.rowKeySet()) {
//			for (Entry<Val, Set<EnsuredCryptSLPredicate>> exPredCell : existingPredicates.row(generatingPredicateStmt).entrySet()) {
//				Set<String> preds = new HashSet<String>();
//				for (EnsuredCryptSLPredicate exPred : exPredCell.getValue()) {
//					preds.add(exPred.getPredicate().getPredName());
//				}
//				for (Entry<CryptSLPredicate, CryptSLPredicate> disPair : contradictionPairs) {
//					if (preds.contains(disPair.getKey().getPredName()) && preds.contains(disPair.getValue().getPredName())) {
//						cryptoScanner.getAnalysisListener().reportError(null, new PredicateContradictionError(generatingPredicateStmt, null, disPair));
//					}
//				}
//			}
//		}
//	}

	
	
	private Table<Statement, IAnalysisSeed, Set<CryptSLPredicate>> computeMissingPredicates() {
		Table<Statement, IAnalysisSeed, Set<CryptSLPredicate>> res = HashBasedTable.create();
		for (Cell<Statement, IAnalysisSeed, Set<CryptSLPredicate>> c : expectedPredicateObjectBased.cellSet()) {
			Set<EnsuredCryptSLPredicate> exPreds = existingPredicatesObjectBased.get(c.getRowKey(), c.getColumnKey());
			if (c.getValue() == null)
				continue;
			HashSet<CryptSLPredicate> expectedPreds = new HashSet<>(c.getValue());
			if (exPreds == null) {
				exPreds = Sets.newHashSet();
			}
			for (EnsuredCryptSLPredicate p : exPreds) {
				expectedPreds.remove(p.getPredicate());
			}
			if (!expectedPreds.isEmpty()) {
				res.put(c.getRowKey(), c.getColumnKey(), expectedPreds);
			}
		}
		return res;
	}

	public void addRequiredPredicate(AnalysisSeedWithSpecification seed, IAnalysisSeed requiringObjectAllocation, RequiredCryptSLPredicate requiredCryptSLPredicate) {
		Set<RequiredCryptSLPredicate> set = requiredPredicates.get(seed, requiringObjectAllocation);
		if(set == null) {
			set = Sets.newHashSet();
		}
		set.add(requiredCryptSLPredicate);
		requiredPredicates.put(seed, requiringObjectAllocation, set);
	}

}
