package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.beust.jcommander.internal.Sets;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.io.Files;

import boomerang.cfg.ExtendedICFG;
import boomerang.cfg.IExtendedICFG;
import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.analysis.ClassSpecification;
import crypto.analysis.CogniCryptCLIReporter;
import crypto.analysis.CryptSLAnalysisListener;
import crypto.analysis.CryptoScanner;
import crypto.rules.CryptSLRule;
import crypto.rules.CryptSLRuleReader;
import crypto.rules.StateNode;
import crypto.typestate.CallSiteWithParamIndex;
import ideal.AnalysisSolver;
import ideal.FactAtStatement;
import ideal.IFactAtStatement;
import ideal.debug.IDEVizDebugger;
import ideal.debug.IDebugger;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.infoflow.android.TestApps.Test;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.util.queue.QueueReader;
import typestate.TypestateDomainValue;

public class PerAPKAnalyzer {
	private static List<String> relevantCalls = Lists.newLinkedList();
	private static FileWriter fout;
	private static boolean runCryptoScanner;
	private static IDebugger<TypestateDomainValue<StateNode>> debugger;
	private static ExtendedICFG icfg;
	private static File ideVizFile;
	private static CogniCryptCLIReporter reporter;
	private static File apkFile;
	public final static String RESOURCE_PATH = "../CryptoAnalysis/src/test/resources/";

	private enum MethodType {
		Application, Library
	}

	private static void readInRelevantCalls() throws FileNotFoundException, IOException {
		String line;
		try (InputStream fis = new FileInputStream("RelevantCalls.txt");
				InputStreamReader isr = new InputStreamReader(fis, Charset.forName("UTF-8"));
				BufferedReader br = new BufferedReader(isr);) {
			while ((line = br.readLine()) != null) {
				relevantCalls.add(line);
			}
		}
	}

	public static IDebugger<TypestateDomainValue<StateNode>> getDebugger() {
		if (debugger == null)
			debugger = new IDEVizDebugger<>(ideVizFile, icfg);
		return debugger;
	}

	public static void main(String... args) throws InterruptedException, IOException {
		readInRelevantCalls();
		apkFile = new File(args[0]);
		// TODO create dir if necessary.
		ideVizFile = new File("target/IDEViz/ide-viz-" + apkFile.getName());
		Test.main(new String[] { args[0], args[1], "--notaintanalysis" });
		ReachableMethods reachableMethods = Scene.v().getReachableMethods();
		QueueReader<MethodOrMethodContext> listener = reachableMethods.listener();
		fout = new FileWriter("Report.txt", true);

		try {
			log(0, "Analyzing " + apkFile.getName());
			Set<SootMethod> visited = Sets.newHashSet();
			while (listener.hasNext()) {
				MethodOrMethodContext next = listener.next();
				analyzeMethod(next.method(), MethodType.Application);
				visited.add(next.method());
			}
			log(1, "Call graph reachable methods: " + visited.size());
			for (SootClass c : Scene.v().getClasses()) {
				for (SootMethod m : c.getMethods()) {
					if (visited.add(m))
						analyzeMethod(m, MethodType.Library);
				}
			}
			log(1, "APK file reachable methods: " + visited.size());
			if (runCryptoScanner) {
				runCryptoAnalysis();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			fout.close();
		}
	}

	protected static List<CryptSLRule> getRules() {
		LinkedList<CryptSLRule> rules = Lists.newLinkedList();
		rules.add(CryptSLRuleReader.readFromFile(new File(RESOURCE_PATH + "Cipher.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(RESOURCE_PATH + "KeyGenerator.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(RESOURCE_PATH + "KeyPairGenerator.cryptslbin")));
		// rules.add(CryptSLRuleReader.readFromFile(new
		// File(IDEALCrossingTestingFramework.RESOURCE_PATH +
		// "MessageDigest.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(RESOURCE_PATH + "PBEKeySpec.cryptslbin")));
		return rules;
	}

	private static void runCryptoAnalysis() {
		icfg = new ExtendedICFG(new JimpleBasedInterproceduralCFG(false));
		reporter = new CogniCryptCLIReporter();
		CryptoScanner scanner = new CryptoScanner(getRules()) {

			@Override
			public IExtendedICFG icfg() {
				return icfg;
			}

			@Override
			public CryptSLAnalysisListener analysisListener() {
				// TODO Auto-generated method stub
				return reporter;
			}

			@Override
			public IDebugger<TypestateDomainValue<StateNode>> debugger() {
				return getDebugger();
			}

		};
		scanner.scan();
		detailedOutput();
		summarizedOutput();
	}

	private static void summarizedOutput() {
		try {
			File file = new File(getSummaryFile());
			boolean fileExisted = true;
			if (!file.exists()) {
				fileExisted = false;
			}
			FileWriter fileWriter = new FileWriter(file, true);
			if (!fileExisted) {
				List<String> line = Lists.newLinkedList();
				line.add("apk_name");
				line.add("analysisSeeds");
				line.add("forbiddenMethodErrors");
				line.add("typestateErrorTimeouts(seed)");
				line.add("typestateError(seed)");
				line.add("typestateError(unit)");
				fileWriter.write(Joiner.on(",").join(line) + "\n");
			}
			List<String> line = Lists.newLinkedList();
			line.add(apkFile.getName());
			line.add(Integer.toString(reporter.getAnalysisSeeds().size()));
			line.add(Integer.toString(reporter.getCallToForbiddenMethod().entries().size()));
			line.add(Integer.toString(reporter.getTypestateTimeouts().size()));
			line.add(Integer.toString(reporter.getTypestateErrors().keySet().size()));
			line.add(Integer.toString(reporter.getTypestateErrors().entries().size()));
			fileWriter.write(Joiner.on(",").join(line) + "\n");
			fileWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static String getSummaryFile() {
		String property = System.getProperty("SummaryFile");
		if (property != null)
			return property;
		return "summary-report.csv";
	}

	private static void detailedOutput() {
		File file = new File("target/reports/cognicrypt/"+apkFile.getName());
		file.getParentFile().mkdirs();
		try {
			FileWriter fileWriter = new FileWriter(file);
			fileWriter.write(reporter.toString());
			fileWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void log(int i, String string) throws IOException {
		String s = "";
		for (int j = 0; j < i; j++) {
			s += "\t";
		}
		fout.write(s + string + " \n");
	}

	private static void analyzeMethod(SootMethod method, MethodType mType) throws IOException {
		if (!method.hasActiveBody())
			return;
		for (Unit u : method.getActiveBody().getUnits()) {
			// if (u instanceof InvokeStmt) {
			for (String relevantCall : relevantCalls)
				if (u.toString().contains(relevantCall)) {
					log(2, mType + "\t Class: " + method.getDeclaringClass() + "  "
							+ method.getDeclaringClass().isApplicationClass() + "\t Method: " + method.getName()
							+ "\t Unit " + u);
					File parentFile = apkFile.getParentFile();
					File dir = new File(parentFile.getAbsolutePath() + File.separator + mType);
					if (!dir.exists()) {
						System.out.println("Created dir " + dir.getAbsolutePath());
						dir.mkdir();
					}
					File copyToFile = new File(dir.getAbsolutePath() + File.separator + apkFile.getName());
					Files.copy(apkFile, copyToFile);
					if (mType == MethodType.Application)
						runCryptoScanner = true;
				}
			// }
		}
	}
}