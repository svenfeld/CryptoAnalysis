package crypto.extractparameter;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.ForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.results.BackwardBoomerangResults;
import crypto.analysis.CryptoScanner;
import crypto.analysis.IAnalysisSeed;
import crypto.boomerang.CogniCryptIntAndStringBoomerangOptions;
import crypto.rules.CryptSLMethod;
import crypto.typestate.CryptSLMethodToSootMethod;
import crypto.typestate.LabeledMatcherTransition;
import crypto.typestate.SootBasedStateMachineGraph;
import heros.utilities.DefaultValueMap;
import soot.Local;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.Stmt;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import sync.pds.solver.nodes.Node;
import typestate.finiteautomata.MatcherTransition;
import wpds.impl.Weight.NoWeight;

public class ExtractParameterAnalysis {

	private Map<Statement, SootMethod> allCallsOnObject;
	private Collection<LabeledMatcherTransition> events = Sets.newHashSet();
	private CryptoScanner cryptoScanner;
	private Multimap<CallSiteWithParamIndex, ForwardQuery> collectedValues = HashMultimap.create();
	private Multimap<CallSiteWithParamIndex, Type> propagatedTypes = HashMultimap.create();
	private DefaultValueMap<AdditionalBoomerangQuery, AdditionalBoomerangQuery> additionalBoomerangQuery = new DefaultValueMap<AdditionalBoomerangQuery, AdditionalBoomerangQuery>() {
		@Override
		protected AdditionalBoomerangQuery createItem(AdditionalBoomerangQuery key) {
			return key;
		}
	};
	private Collection<CallSiteWithParamIndex> querySites = Sets.newHashSet();

	public ExtractParameterAnalysis(CryptoScanner cryptoScanner, Map<Statement, SootMethod> allCallsOnObject,
			SootBasedStateMachineGraph fsm) {
		this.cryptoScanner = cryptoScanner;
		this.allCallsOnObject = allCallsOnObject;
		for (MatcherTransition m : fsm.getAllTransitions()) {
			if (m instanceof LabeledMatcherTransition) {
				this.events.add((LabeledMatcherTransition) m);
			}
		}
	}

	public void findDataFlowForNonRuleTypes() {
		for(Entry<CryptSLMethod, Node<Statement, SootMethod>> e : getCalledMethodAtEventsOfObject().entries()) {
			CryptSLMethod matchingDescriptor = e.getKey();
			SootMethod method = e.getValue().fact();
			int index = 0;
			for (Entry<String, String> param : matchingDescriptor.getParameters()) {
				if (!param.getKey().equals("_")) {
					soot.Type parameterType = method.getParameterType(index);
					// Ignore parameters for whose types a rule exists. These flows will be computed
					// in AnalysisSeedWithSpecification
					if (cryptoScanner.hasRulesForType(parameterType)) {
						continue;
					}
					if (parameterType.toString().equals(param.getValue())) {
						addQueryAtCallsite(param.getKey(), e.getValue().stmt(), index);
					}
				}
				index++;
			}
		}
		for (AdditionalBoomerangQuery q : additionalBoomerangQuery.keySet()) {
			q.solve();
		}
	}

	public Multimap<CryptSLMethod, Node<Statement,SootMethod>> getCalledMethodAtEventsOfObject() {
		Multimap<CryptSLMethod, Node<Statement,SootMethod>> res = HashMultimap.create();
		for (Entry<Statement, SootMethod> callSiteWithCallee : allCallsOnObject.entrySet()) {
			Statement callSite = callSiteWithCallee.getKey();
			SootMethod declaredCallee = callSiteWithCallee.getValue();
			if (!callSite.isCallsite()) {
				continue;
			}
			for (LabeledMatcherTransition e : events) {
				if (e.matches(declaredCallee)) {
					for (CryptSLMethod matchingDescriptor : e.label()) {
						for (SootMethod m : CryptSLMethodToSootMethod.v().convert(matchingDescriptor)) {
							SootMethod method = callSite.getUnit().get().getInvokeExpr().getMethod();
							if (!m.equals(method))
								continue;
							res.put(matchingDescriptor, new Node<Statement,SootMethod>(callSite, m));
						}
					}
				}
			}
		}
		return res;
	}

	public void combineDataFlows() {
		for(Entry<CryptSLMethod, Node<Statement,SootMethod>> e : getCalledMethodAtEventsOfObject().entries()) {
			CryptSLMethod matchingDescriptor = e.getKey();
			SootMethod method = e.getValue().fact();
			Statement callSite = e.getValue().stmt();
			int index = 0;
			for (Entry<String, String> param : matchingDescriptor.getParameters()) {
				if (!param.getKey().equals("_")) {
					soot.Type parameterType = method.getParameterType(index);
					// Ignore parameters for whose types a rule exists. These flows will be computed
					// in AnalysisSeedWithSpecification
					if (cryptoScanner.hasRulesForType(parameterType)) {
						if (parameterType.toString().equals(param.getValue())) {
							Value parameter = callSite.getUnit().get().getInvokeExpr().getArg(index);
							Val queryVal = new Val((Local) parameter, callSite.getMethod());
							CallSiteWithParamIndex callSiteWithParamIndex = new CallSiteWithParamIndex(callSite, queryVal, index,
									param.getKey());
							Set<IAnalysisSeed> reachingSeeds = cryptoScanner.findSeedsForValAtStatement(new Node<Statement,Val>(callSite, queryVal));
							collectedValues.putAll(callSiteWithParamIndex, reachingSeeds);
						}						
					}
				}
				index++;
			}
		}
	}

	public Multimap<CallSiteWithParamIndex, ForwardQuery> getCollectedValues() {
		return collectedValues;
	}

	public Multimap<CallSiteWithParamIndex, Type> getPropagatedTypes() {
		return propagatedTypes;
	}

	public Collection<CallSiteWithParamIndex> getAllQuerySites() {
		return querySites;
	}

	public void addQueryAtCallsite(final String varNameInSpecification, final Statement stmt, final int index) {
		if (!stmt.isCallsite())
			return;
		Value parameter = stmt.getUnit().get().getInvokeExpr().getArg(index);
		if (!(parameter instanceof Local)) {
			CallSiteWithParamIndex cs = new CallSiteWithParamIndex(stmt, new Val(parameter, stmt.getMethod()), index,
					varNameInSpecification);
			collectedValues.put(cs, new ForwardQuery(stmt, new AllocVal(parameter, stmt.getMethod(), parameter, stmt)));
			querySites.add(cs);
			throw new RuntimeException("Unreachable");
		}
		Val queryVal = new Val((Local) parameter, stmt.getMethod());

		for (Unit pred : cryptoScanner.icfg().getPredsOf(stmt.getUnit().get())) {
			AdditionalBoomerangQuery query = additionalBoomerangQuery
					.getOrCreate(new AdditionalBoomerangQuery(new Statement((Stmt) pred, stmt.getMethod()), queryVal));
			CallSiteWithParamIndex callSiteWithParamIndex = new CallSiteWithParamIndex(stmt, queryVal, index,
					varNameInSpecification);
			querySites.add(callSiteWithParamIndex);
			query.addListener(new QueryListener() {
				@Override
				public void solved(AdditionalBoomerangQuery q, BackwardBoomerangResults<NoWeight> res) {
					propagatedTypes.putAll(callSiteWithParamIndex, res.getPropagationType());
					collectedValues.putAll(callSiteWithParamIndex, res.getAllocationSites().keySet());
					// for (ForwardQuery v : res.getAllocationSites().keySet()) {
					// ExtractedValue extractedValue = null;
					// if(v.var() instanceof AllocVal) {
					// AllocVal allocVal = (AllocVal) v.var();
					// extractedValue = new
					// ExtractedValue(allocVal.allocationStatement(),allocVal.allocationValue());
					// } else {
					// extractedValue = new ExtractedValue(v.stmt(),v.var().value());
					// }
					// }
				}
			});
		}
	}

	public void addAdditionalBoomerangQuery(AdditionalBoomerangQuery q, QueryListener listener) {
		AdditionalBoomerangQuery query = additionalBoomerangQuery.getOrCreate(q);
		query.addListener(listener);
	}

	public class AdditionalBoomerangQuery extends BackwardQuery {
		public AdditionalBoomerangQuery(Statement stmt, Val variable) {
			super(stmt, variable);
		}

		protected boolean solved;
		private List<QueryListener> listeners = Lists.newLinkedList();
		private BackwardBoomerangResults<NoWeight> res;

		public void solve() {
			Boomerang boomerang = new Boomerang(new CogniCryptIntAndStringBoomerangOptions()) {
				@Override
				public BiDiInterproceduralCFG<Unit, SootMethod> icfg() {
					return ExtractParameterAnalysis.this.cryptoScanner.icfg();
				}
			};
			res = boomerang.solve(this);
			for (QueryListener l : Lists.newLinkedList(listeners)) {
				l.solved(this, res);
			}
			solved = true;
		}

		public void addListener(QueryListener q) {
			if (solved) {
				q.solved(this, res);
				return;
			}
			listeners.add(q);
		}

	}

	private static interface QueryListener {
		public void solved(AdditionalBoomerangQuery q, BackwardBoomerangResults<NoWeight> res);
	}

}
