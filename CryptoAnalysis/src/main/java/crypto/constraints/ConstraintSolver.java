package crypto.constraints;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.base.Optional;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import boomerang.ForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.analysis.ClassSpecification;
import crypto.analysis.CrySLResultsReporter;
import crypto.analysis.IAnalysisSeed;
import crypto.analysis.RequiredCryptSLPredicate;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.ConstraintError;
import crypto.analysis.errors.ForbiddenMethodError;
import crypto.analysis.errors.ImpreciseValueExtractionError;
import crypto.analysis.errors.NeverTypeOfError;
import crypto.extractparameter.CallSiteWithExtractedValue;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.interfaces.ICryptSLPredicateParameter;
import crypto.interfaces.ISLConstraint;
import crypto.predicates.PredicateHandler;
import crypto.rules.CryptSLArithmeticConstraint;
import crypto.rules.CryptSLComparisonConstraint;
import crypto.rules.CryptSLConstraint;
import crypto.rules.CryptSLConstraint.LogOps;
import crypto.rules.CryptSLMethod;
import crypto.rules.CryptSLObject;
import crypto.rules.CryptSLPredicate;
import crypto.rules.CryptSLSplitter;
import crypto.rules.CryptSLValueConstraint;
import crypto.typestate.CryptSLMethodToSootMethod;
import soot.IntType;
import soot.SootMethod;
import soot.Type;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.IntConstant;
import soot.jimple.LongConstant;
import soot.jimple.NullConstant;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;

public class ConstraintSolver {

	private final List<ISLConstraint> allConstraints;
	private final Set<ISLConstraint> relConstraints = Sets.newHashSet();
	private final Collection<Statement> collectedCalls;
	private final Multimap<CallSiteWithParamIndex, ForwardQuery> parsAndVals;
	public final static List<String> predefinedPreds = Arrays.asList("callTo", "noCallTo", "neverTypeOf", "length");
	private final CrySLResultsReporter reporter;
	private final AnalysisSeedWithSpecification seed;
	private final ClassSpecification classSpec;
	private Collection<CallSiteWithParamIndex> parameterAnalysisQuerySites;
	private Multimap<CallSiteWithParamIndex, Type> propagatedTypes;

	public ConstraintSolver(AnalysisSeedWithSpecification seed, CrySLResultsReporter crySLResultsReporter) {
		this.seed = seed;
		this.classSpec = seed.getSpec();
		this.parsAndVals = seed.getParameterAnalysis().getCollectedValues();
		this.propagatedTypes = seed.getParameterAnalysis().getPropagatedTypes();
		this.parameterAnalysisQuerySites = seed.getParameterAnalysis().getCollectedValues().keySet();
		this.collectedCalls = seed.getAllCallsOnObject().keySet();
		this.allConstraints = this.classSpec.getRule().getConstraints();
		this.reporter = crySLResultsReporter;
	}

	public int evaluateRelConstraints() {
		for (ISLConstraint cons : allConstraints) {

			Set<String> involvedVarNames = cons.getInvolvedVarNames();
			for (CallSiteWithParamIndex cwpi : this.parameterAnalysisQuerySites) {
				involvedVarNames.remove(cwpi.getVarName());
			}

			if (involvedVarNames.isEmpty()) {
				if (cons instanceof CryptSLPredicate) {
					CryptSLPredicate pred = (CryptSLPredicate) cons;
					for (Entry<CallSiteWithParamIndex, ForwardQuery> e : seed.getParameterAnalysis()
							.getCollectedValues().entries()) {
						CallSiteWithParamIndex cwpi = e.getKey();
						for (ICryptSLPredicateParameter param : pred.getParameters()) {
							if (cwpi.getVarName().equals(param.getName())) {
								// TODO: FIX Cipher rule
								if (param.getName().equals("transformation"))
									continue;
								relConstraints.add(pred);
								seed.addRequiredPredicate(e.getValue(),
										new RequiredCryptSLPredicate(pred, cwpi.stmt()), cwpi);
							}
						}

					}
				} else {
					relConstraints.add(cons);
				}
			}
		}

		int fail = 0;
		for (ISLConstraint con : relConstraints) {
			EvaluableConstraint currentConstraint = createConstraint(con);
			currentConstraint.evaluate();
			for (AbstractError e : currentConstraint.getErrors()) {
				if (e instanceof ImpreciseValueExtractionError) {
					reporter.reportError(seed,
							new ImpreciseValueExtractionError(con, e.getErrorLocation(), e.getRule()));
					break;
				} else {
					fail++;
					reporter.reportError(seed, e);
				}
			}
		}
		return fail;
	}

	public EvaluableConstraint createConstraint(ISLConstraint con) {
		if (con instanceof CryptSLComparisonConstraint) {
			return new ComparisonConstraint((CryptSLComparisonConstraint) con);
		} else if (con instanceof CryptSLValueConstraint) {
			return new ValueConstraint((CryptSLValueConstraint) con);
		} else if (con instanceof CryptSLPredicate) {
			return new PredicateConstraint((CryptSLPredicate) con);
		} else if (con instanceof CryptSLConstraint) {
			return new BinaryConstraint((CryptSLConstraint) con);
		}
		return null;
	}

	/**
	 * @return the allConstraints
	 */
	public List<ISLConstraint> getAllConstraints() {
		return allConstraints;
	}

	private class BinaryConstraint extends EvaluableConstraint {

		public BinaryConstraint(CryptSLConstraint c) {
			super(c);
		}

		@Override
		public void evaluate() {
			CryptSLConstraint binaryConstraint = (CryptSLConstraint) origin;
			EvaluableConstraint left = createConstraint(binaryConstraint.getLeft());
			EvaluableConstraint right = createConstraint(binaryConstraint.getRight());
			left.evaluate();
			LogOps ops = binaryConstraint.getOperator();

			if (ops.equals(LogOps.implies)) {
				if (left.hasErrors()) {
					return;
				} else {
					right.evaluate();
					errors.addAll(right.getErrors());
					return;
				}
			} else if (ops.equals(LogOps.or)) {
				right.evaluate();
				errors.addAll(left.getErrors());
				errors.addAll(right.getErrors());
				return;
			} else if (ops.equals(LogOps.and)) {
				if (left.hasErrors()) {
					errors.addAll(left.getErrors());
					return;
				} else {
					right.evaluate();
					errors.addAll(right.getErrors());
					return;
				}
			} else if (ops.equals(LogOps.eq)) {
				right.evaluate();
				if ((left.hasErrors() && right.hasErrors()) || (!left.hasErrors() && !right.hasErrors())) {
					return;
				} else {
					errors.addAll(right.getErrors());
					return;
				}
			}
			errors.addAll(left.getErrors());
		}

	}

	public class PredicateConstraint extends EvaluableConstraint {

		public PredicateConstraint(CryptSLPredicate c) {
			super(c);
		}

		@Override
		public void evaluate() {
			CryptSLPredicate predicateConstraint = (CryptSLPredicate) origin;
			String predName = predicateConstraint.getPredName();
			if (predefinedPreds.contains(predName)) {
				handlePredefinedNames(predicateConstraint);
			}
		}

		private void handlePredefinedNames(CryptSLPredicate pred) {

			List<ICryptSLPredicateParameter> parameters = pred.getParameters();
			switch (pred.getPredName()) {
			case "callTo":
				List<ICryptSLPredicateParameter> predMethods = parameters;
				for (ICryptSLPredicateParameter predMethod : predMethods) {
					// check whether predMethod is in foundMethods, which type-state analysis has to
					// figure out
					CryptSLMethod reqMethod = (CryptSLMethod) predMethod;
					for (Statement unit : collectedCalls) {
						if (!(unit.isCallsite()))
							continue;
						SootMethod foundCall = ((Stmt) unit.getUnit().get()).getInvokeExpr().getMethod();
						Collection<SootMethod> convert = CryptSLMethodToSootMethod.v().convert(reqMethod);
						if (convert.contains(foundCall)) {
							return;
						}
					}
				}
				// TODO: Need seed here.
				return;
			case "noCallTo":
				if (collectedCalls.isEmpty()) {
					return;
				}
				List<ICryptSLPredicateParameter> predForbiddenMethods = parameters;
				for (ICryptSLPredicateParameter predForbMethod : predForbiddenMethods) {
					// check whether predForbMethod is in foundForbMethods, which forbidden-methods
					// analysis has to figure out
					CryptSLMethod reqMethod = ((CryptSLMethod) predForbMethod);

					for (Statement call : collectedCalls) {
						if (!call.isCallsite())
							continue;
						SootMethod foundCall = call.getUnit().get().getInvokeExpr().getMethod();
						Collection<SootMethod> convert = CryptSLMethodToSootMethod.v().convert(reqMethod);
						if (convert.contains(foundCall)) {
							errors.add(new ForbiddenMethodError(call, classSpec.getRule(), foundCall, convert));
							return;
						}
					}
				}
				return;
			case "neverTypeOf":
				// pred looks as follows: neverTypeOf($varName, $type)
				// -> first parameter is always the variable
				// -> second parameter is always the type
				String varName = ((CryptSLObject) parameters.get(0)).getVarName();
				for (CallSiteWithParamIndex cs : parameterAnalysisQuerySites) {
					if (cs.getVarName().equals(varName)) {
						Collection<Type> vals = propagatedTypes.get(cs);
						for (Type t : vals) {
							if (t.toQuotedString().equals(parameters.get(1).getName())) {
								errors.add(new NeverTypeOfError(new CallSiteWithExtractedValue(cs, null),
										classSpec.getRule(), seed, pred));
							}
						}
					}
				}

				return;
			case "length":
				// pred looks as follows: neverTypeOf($varName)
				// -> parameter is always the variable
				String var = ((CryptSLObject) pred.getParameters().get(0)).getVarName();
				for (CallSiteWithParamIndex cs : parsAndVals.keySet()) {
					if (cs.getVarName().equals(var)) {
						errors.add(new ImpreciseValueExtractionError(origin, cs.stmt(), classSpec.getRule()));
						break;
					}
				}
				return;
			default:
				return;
			}
		}
	}

	public class ComparisonConstraint extends EvaluableConstraint {

		public ComparisonConstraint(CryptSLComparisonConstraint c) {
			super(c);
		}

		@Override
		public void evaluate() {
			CryptSLComparisonConstraint compConstraint = (CryptSLComparisonConstraint) origin;

			Map<Long, CallSiteWithExtractedValue> left = evaluate(compConstraint.getLeft());
			Map<Long, CallSiteWithExtractedValue> right = evaluate(compConstraint.getRight());

			for (Entry<Long, CallSiteWithExtractedValue> entry : right.entrySet()) {
				if (entry.getKey() == Integer.MIN_VALUE) {
					errors.add(new ConstraintError(entry.getValue(), classSpec.getRule(), seed, compConstraint));
					return;
				}
			}

			for (Entry<Long, CallSiteWithExtractedValue> leftie : left.entrySet()) {
				if (leftie.getKey() == Integer.MIN_VALUE) {
					errors.add(new ConstraintError(leftie.getValue(), classSpec.getRule(), seed, compConstraint));
					return;
				}
				for (Entry<Long, CallSiteWithExtractedValue> rightie : right.entrySet()) {

					boolean cons = true;
					switch (compConstraint.getOperator()) {
					case eq:
						cons = leftie.getKey().equals(rightie.getKey());
						break;
					case g:
						cons = leftie.getKey() > rightie.getKey();
						break;
					case ge:
						cons = leftie.getKey() >= rightie.getKey();
						break;
					case l:
						cons = leftie.getKey() < rightie.getKey();
						break;
					case le:
						cons = leftie.getKey() <= rightie.getKey();
						break;
					case neq:
						cons = leftie.getKey() != rightie.getKey();
						break;
					default:
						cons = false;
					}
					if (!cons) {
						errors.add(new ConstraintError(leftie.getValue(), classSpec.getRule(), seed, origin));
						return;
					}
				}
			}
		}

		private Map<Long, CallSiteWithExtractedValue> evaluate(CryptSLArithmeticConstraint arith) {
			Map<Long, CallSiteWithExtractedValue> left = extractValueAsInt(arith.getLeft(), arith);
			Map<Long, CallSiteWithExtractedValue> right = extractValueAsInt(arith.getRight(), arith);
			for (Entry<Long, CallSiteWithExtractedValue> rightie : right.entrySet()) {
				if (rightie.getKey() == Integer.MIN_VALUE) {
					return left;
				}
			}

			Map<Long, CallSiteWithExtractedValue> results = new HashMap<>();
			for (Entry<Long, CallSiteWithExtractedValue> leftie : left.entrySet()) {
				if (leftie.getKey() == Integer.MIN_VALUE) {
					return left;
				}

				for (Entry<Long, CallSiteWithExtractedValue> rightie : right.entrySet()) {
					long sum = 0;
					switch (arith.getOperator()) {
					case n:
						sum = leftie.getKey() - rightie.getKey();
						break;
					case p:
						sum = leftie.getKey() + rightie.getKey();
						break;
					default:
						sum = 0;
					}
					if (rightie.getValue() != null) {
						results.put(sum, rightie.getValue());
					} else {
						results.put(sum, leftie.getValue());
					}
				}
			}
			return results;
		}

		private Map<Long, CallSiteWithExtractedValue> extractValueAsInt(ICryptSLPredicateParameter par,
				CryptSLArithmeticConstraint arith) {
			if (par instanceof CryptSLPredicate) {
				PredicateConstraint predicateConstraint = new PredicateConstraint((CryptSLPredicate) par);
				predicateConstraint.evaluate();
				if (!predicateConstraint.getErrors().isEmpty()) {
					for (AbstractError err : predicateConstraint.getErrors()) {
						errors.add(new ImpreciseValueExtractionError(arith, err.getErrorLocation(), err.getRule()));
					}
					predicateConstraint.errors.clear();
				}
				return new HashMap<Long, CallSiteWithExtractedValue>();
			} else {
				return extractValueAsInt(par.getName(), arith);
			}
		}

		private Map<Long, CallSiteWithExtractedValue> extractValueAsInt(String exp, ISLConstraint cons) {
			final HashMap<Long, CallSiteWithExtractedValue> valuesInt = new HashMap<>();
			try {
				// 1. exp may (already) be an integer
				valuesInt.put((long) Integer.parseInt(exp), null);
				return valuesInt;
			} catch (NumberFormatException ex) {
				// 2. If not, it's a variable name.
				// Get value of variable left from map
				final Entry<List<AllocVal>, CallSiteWithExtractedValue> valueCollection = extractValueAsString(exp,
						cons);
				if (valueCollection.getKey().isEmpty()) {
					return valuesInt;
				}
				for (AllocVal value : valueCollection.getKey()) {
					Optional<Long> v = getIntegerValue(value);
					if (v.isPresent()) {
						valuesInt.put(v.get(), valueCollection.getValue());
					}
				}
				return valuesInt;
			}
		}

	}

	public class ValueConstraint extends EvaluableConstraint {

		public ValueConstraint(CryptSLValueConstraint c) {
			super(c);
		}

		@Override
		public void evaluate() {
			CryptSLValueConstraint valCons = (CryptSLValueConstraint) origin;

			CryptSLObject var = valCons.getVar();
			final List<Entry<String, CallSiteWithExtractedValue>> vals = getValFromVar(var, valCons);
			if (vals.isEmpty()) {
				// TODO: Check whether this works as desired
				return;
			}
			for (Entry<String, CallSiteWithExtractedValue> val : vals) {
				if (!valCons.getValueRange().contains(val.getKey())) {
					errors.add(new ConstraintError(val.getValue(), classSpec.getRule(), seed, valCons));
					return;
				}
			}
			return;
		}

		private List<Entry<String, CallSiteWithExtractedValue>> getValFromVar(CryptSLObject var, ISLConstraint cons) {
			final String varName = var.getVarName();
			final Entry<List<AllocVal>, CallSiteWithExtractedValue> valueCollection = extractValueAsString(varName,
					cons);
			List<Entry<String, CallSiteWithExtractedValue>> vals = new ArrayList<>();
			if (valueCollection.getKey().isEmpty()) {
				return vals;
			}
			for (AllocVal allocVal : valueCollection.getKey()) {

				final CallSiteWithExtractedValue location = valueCollection.getValue();
				Optional<Long> intVal = getIntegerValue(allocVal);
				if (intVal.isPresent()) {
					vals.add(new AbstractMap.SimpleEntry<>(intVal.get().toString(), location));
				} else {
					Optional<String> v = getStringValue(allocVal);
					if (!v.isPresent()) {
						continue;
					}
					String val = v.get();
					CryptSLSplitter splitter = var.getSplitter();
					if (splitter != null) {
						int ind = splitter.getIndex();
						String splitElement = splitter.getSplitter();
						if (ind > 0) {
							String[] splits = val.split(splitElement);
							if (splits.length > ind) {
								vals.add(new AbstractMap.SimpleEntry<>(splits[ind], location));
							} else {
								vals.add(new AbstractMap.SimpleEntry<>("", location));
							}
						} else {
							vals.add(new AbstractMap.SimpleEntry<>(val.split(splitElement)[ind], location));
						}
					} else {
						vals.add(new AbstractMap.SimpleEntry<>(val, location));
					}
				}
			}
			return vals;
		}

	}

	public abstract class EvaluableConstraint {

		Set<AbstractError> errors = Sets.newHashSet();
		ISLConstraint origin;

		public abstract void evaluate();

		public EvaluableConstraint(ISLConstraint con) {
			origin = con;
		}

		protected Collection<AbstractError> getErrors() {
			return errors;
		};

		public boolean hasErrors() {
			return !errors.isEmpty();
		}

		protected Entry<List<AllocVal>, CallSiteWithExtractedValue> extractValueAsString(String varName,
				ISLConstraint cons) {
			List<AllocVal> varVal = Lists.newArrayList();
			CallSiteWithExtractedValue witness = null;
			for (Entry<CallSiteWithParamIndex, ForwardQuery> e : parsAndVals.entries()) {
				CallSiteWithParamIndex wrappedCallSite = e.getKey();
				ForwardQuery wrappedAllocSite = e.getValue();
				if (!wrappedCallSite.getVarName().equals(varName)) {
					continue;
				}
				if (wrappedAllocSite.var() instanceof AllocVal) {
					AllocVal allocVal = (AllocVal) wrappedAllocSite.var();
					varVal.add(allocVal);
					witness = new CallSiteWithExtractedValue(wrappedCallSite,
							ExtractedValue.fromQuery(wrappedAllocSite));
				}
			}
			return new AbstractMap.SimpleEntry<List<AllocVal>, CallSiteWithExtractedValue>(varVal, witness);
		}
	}

	public Optional<String> getStringValue(AllocVal val) {
		Value v = val.allocationValue();
		if (v instanceof StringConstant) {
			StringConstant sConstant = (StringConstant) v;
			return Optional.of(sConstant.value);
		}
		return Optional.absent();
	}

	public Optional<Long> getIntegerValue(AllocVal val) {
		Value v = val.allocationValue();
		if (v instanceof IntConstant) {
			IntConstant intConstant = (IntConstant) v;
			return Optional.of((long) intConstant.value);
		} else if (v instanceof LongConstant) {
			LongConstant longConstant = (LongConstant) v;
			return Optional.of(longConstant.value);
		}
		return Optional.absent();
	}
}