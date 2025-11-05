package edu.berkeley.cs.jqf.fuzz.predicates;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * An extension of ZestGuidance that tracks line-level coverage for predicates
 * identified through static analysis.
 *
 * This class extends ZestGuidance and adds line coverage tracking for specific
 * lines from the predicate JSON file.
 */
public class PredicateTrackingGuidance extends ZestGuidance {

    private final LineCoverage lineCoverage;
    private final List<PredicateTarget> predicateTargets;
    private int inputCounter = 0;
    private final String outputPath;

    /**
     * Creates a new PredicateTrackingGuidance.
     *
     * @param testName the name of the test
     * @param duration the duration to run fuzzing
     * @param trials the maximum number of trials
     * @param outputDirectory the output directory
     * @param seedInputDir the seed input directory (can be null)
     * @param sourceOfRandomness the random number generator
     * @param predicateTargets the predicate targets from static analysis
     * @param lineCoverageOutputPath path to write line coverage JSON
     * @throws IOException if there's an error setting up directories
     */
    public PredicateTrackingGuidance(String testName, Duration duration, Long trials,
                                    File outputDirectory, File seedInputDir, Random sourceOfRandomness,
                                    List<PredicateTarget> predicateTargets, String lineCoverageOutputPath)
            throws IOException {
        super(testName, duration, trials, outputDirectory, seedInputDir, sourceOfRandomness);
        this.predicateTargets = predicateTargets;
        this.lineCoverage = new LineCoverage(predicateTargets);
        this.outputPath = lineCoverageOutputPath;

        System.out.println("=== Predicate Tracking Enabled ===");
        System.out.println("Tracking " + predicateTargets.size() + " predicates");
        int totalLines = 0;
        for (PredicateTarget pred : predicateTargets) {
            totalLines += 1 + pred.getBranches().size(); // predicate line + branch lines
        }
        System.out.println("Tracking " + totalLines + " total lines");
        System.out.println();

        // Add shutdown hook to save results even if interrupted
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n=== Fuzzing interrupted, saving line coverage results ===");
            printLineCoverageStats();
            if (outputPath != null) {
                try {
                    writeLineCoverageJson(outputPath);
                } catch (IOException e) {
                    System.err.println("Error writing line coverage JSON: " + e.getMessage());
                }
            }
        }));
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        inputCounter++;
        lineCoverage.setCurrentInputId(inputCounter);
        return super.getInput();
    }

    @Override
    public boolean hasInput() {
        boolean hasMore = super.hasInput();
        if (!hasMore) {
            // Fuzzing is done, print statistics
            printLineCoverageStats();
            if (outputPath != null) {
                try {
                    writeLineCoverageJson(outputPath);
                } catch (IOException e) {
                    System.err.println("Error writing line coverage JSON: " + e.getMessage());
                }
            }
        }
        return hasMore;
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        Consumer<TraceEvent> superCallback = super.generateCallBack(thread);

        return (event) -> {
            // First, pass to super for normal Zest coverage tracking
            superCallback.accept(event);

            // Then track line coverage for our targets
            lineCoverage.handleEvent(event);
        };
    }

    @Override
    protected void displayStats(boolean force) {
        // We need to override completely to include predicate stats in the cleared screen
        // First, let the parent do its timing/throttling checks and return if not time to update
        Date now = new Date();
        long intervalMilliseconds = now.getTime() - lastRefreshTime.getTime();
        intervalMilliseconds = Math.max(1, intervalMilliseconds);
        if (intervalMilliseconds < STATS_REFRESH_TIME_PERIOD && !force) {
            return;
        }

        // Call super to print all the normal Zest stats (which clears screen first)
        super.displayStats(force);

        // Then add our predicate coverage stats (after super has printed but before next screen clear)
        if (!QUIET_MODE && !LIBFUZZER_COMPAT_OUTPUT && console != null) {
            // Count how many predicates have been hit
            int hitCount = 0;
            for (PredicateTarget pred : predicateTargets) {
                if (lineCoverage.getInputCount(pred.getClassName(), pred.getPredicateLine()) > 0) {
                    hitCount++;
                }
            }

            console.printf("Predicates hit:       %d/%d\n", hitCount, predicateTargets.size());

            // Show top 5 predicates by dominance score (already sorted in JSON)
            console.printf("Top predicates:\n");
            int displayCount = Math.min(5, predicateTargets.size());
            for (int i = 0; i < displayCount; i++) {
                PredicateTarget pred = predicateTargets.get(i);
                int predCount = lineCoverage.getInputCount(pred.getClassName(), pred.getPredicateLine());

                console.printf("  %s:%d (method: %s, dom: %d) - %d inputs (%.1f%%)\n",
                    pred.getClassName(), pred.getPredicateLine(),
                    pred.getMethodName(), pred.getDominanceScore(),
                    predCount, (100.0 * predCount / Math.max(1, inputCounter)));

                // Show branches for this predicate
                for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                    int branchCount = lineCoverage.getInputCount(branch.getClassName(), branch.getLine());
                    double branchPercentage = (predCount > 0) ? (100.0 * branchCount / predCount) : 0.0;
                    console.printf("    Branch line %d: %d inputs (%.1f%% of predicate) [dom: %d]\n",
                        branch.getLine(), branchCount, branchPercentage, branch.getDominance());
                }
            }
        }
    }

    @Override
    protected String getTitle() {
        return  "Semantic Fuzzing with Zest + Predicate Tracking\n" +
                "------------------------------------------------\n";
    }

    private String shortenClassName(String fullClassName) {
        // Remove package prefix, keep only simple class name
        int lastDot = fullClassName.lastIndexOf('.');
        int lastSlash = fullClassName.lastIndexOf('/');
        int splitPos = Math.max(lastDot, lastSlash);
        return splitPos >= 0 ? fullClassName.substring(splitPos + 1) : fullClassName;
    }

    /**
     * Prints line coverage statistics to stdout.
     */
    private void printLineCoverageStats() {
        System.out.println();
        System.out.println("=== LINE COVERAGE STATISTICS ===");
        System.out.println("Total inputs generated: " + inputCounter);
        System.out.println();

        for (PredicateTarget pred : predicateTargets) {
            String className = pred.getClassName();
            int predLine = pred.getPredicateLine();

            System.out.printf("Predicate: %s:%d (method: %s, dominance: %d)%n",
                    className, predLine, pred.getMethodName(), pred.getDominanceScore());

            int predCount = lineCoverage.getInputCount(className, predLine);
            System.out.printf("  Predicate line %d: %d inputs (%.1f%%)%n",
                    predLine, predCount, (100.0 * predCount / inputCounter));

            for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                int branchCount = lineCoverage.getInputCount(branch.getClassName(), branch.getLine());
                // Show branch percentage relative to predicate inputs, not total inputs
                double branchPercentage = (predCount > 0) ? (100.0 * branchCount / predCount) : 0.0;
                System.out.printf("    Branch line %d: %d inputs (%.1f%% of predicate) [dominance: %d]%n",
                        branch.getLine(), branchCount,
                        branchPercentage,
                        branch.getDominance());
            }

            System.out.println();
        }
    }

    /**
     * Writes line coverage statistics to JSON file.
     */
    private void writeLineCoverageJson(String path) throws IOException {
        Map<String, Object> output = new HashMap<>();
        output.put("totalInputs", inputCounter);

        // Build line coverage data
        Map<String, Object>[] lineCoverageData = new Map[predicateTargets.size()];

        for (int i = 0; i < predicateTargets.size(); i++) {
            PredicateTarget pred = predicateTargets.get(i);
            Map<String, Object> predicateData = new HashMap<>();

            predicateData.put("class", pred.getClassName());
            predicateData.put("method", pred.getMethodName());
            predicateData.put("predicateLine", pred.getPredicateLine());
            predicateData.put("dominanceScore", pred.getDominanceScore());

            int predCount = lineCoverage.getInputCount(pred.getClassName(), pred.getPredicateLine());
            predicateData.put("predicateInputs", predCount);

            // Branch data
            Map<String, Object>[] branchData = new Map[pred.getBranches().size()];
            for (int j = 0; j < pred.getBranches().size(); j++) {
                PredicateTarget.BranchTarget branch = pred.getBranches().get(j);
                Map<String, Object> branchMap = new HashMap<>();

                branchMap.put("line", branch.getLine());
                branchMap.put("dominance", branch.getDominance());

                int branchCount = lineCoverage.getInputCount(branch.getClassName(), branch.getLine());
                branchMap.put("inputs", branchCount);

                branchData[j] = branchMap;
            }

            predicateData.put("branches", branchData);
            lineCoverageData[i] = predicateData;
        }

        output.put("lineCoverage", lineCoverageData);

        // Write JSON
        ObjectMapper mapper = new ObjectMapper();
        try (FileWriter writer = new FileWriter(path)) {
            mapper.writerWithDefaultPrettyPrinter().writeValue(writer, output);
        }

        System.out.println("Line coverage statistics written to: " + path);
    }

    /**
     * Gets the line coverage tracker.
     *
     * @return the line coverage object
     */
    public LineCoverage getLineCoverage() {
        return lineCoverage;
    }
}
