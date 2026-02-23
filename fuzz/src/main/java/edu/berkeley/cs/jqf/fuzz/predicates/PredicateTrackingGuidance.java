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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
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

            // Collect all branches with their coverage info
            java.util.List<BranchInfo> uncoveredBranches = new java.util.ArrayList<>();
            for (PredicateTarget pred : predicateTargets) {
                int predCount = lineCoverage.getInputCount(pred.getClassName(), pred.getPredicateLine());
                // Only consider branches where the predicate has been hit
                if (predCount > 0) {
                    for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                        int branchCount = lineCoverage.getInputCount(branch.getClassName(), branch.getLine());
                        double branchPercentage = (predCount > 0) ? (100.0 * branchCount / predCount) : 0.0;
                        uncoveredBranches.add(new BranchInfo(pred, branch, predCount, branchCount, branchPercentage));
                    }
                }
            }

            // Sort by dominance (descending), then by coverage percentage (ascending)
            // This prioritizes high-dominance branches that are least covered
            uncoveredBranches.sort((a, b) -> {
                int domCompare = Integer.compare(b.branch.getDominance(), a.branch.getDominance());
                if (domCompare != 0) return domCompare;
                return Double.compare(a.branchPercentage, b.branchPercentage);
            });

            // Show top 5 most important under-covered branches
            if (!uncoveredBranches.isEmpty()) {
                console.printf("\nTop under-covered branches (sorted by dominance, then by %% coverage):\n");
                int uncoveredDisplayCount = Math.min(5, uncoveredBranches.size());
                for (int i = 0; i < uncoveredDisplayCount; i++) {
                    BranchInfo info = uncoveredBranches.get(i);
                    console.printf("  %s:%d -> line %d [dom: %d, %.1f%% coverage]\n",
                        info.predicate.getClassName(), info.predicate.getPredicateLine(),
                        info.branch.getLine(), info.branch.getDominance(), info.branchPercentage);
                }
            }
        }
    }

    // Helper class to hold predicate+branch info for sorting
    private static class BranchInfo {
        final PredicateTarget predicate;
        final PredicateTarget.BranchTarget branch;
        final int predicateCount;
        final int branchCount;
        final double branchPercentage;

        BranchInfo(PredicateTarget predicate, PredicateTarget.BranchTarget branch,
                   int predicateCount, int branchCount, double branchPercentage) {
            this.predicate = predicate;
            this.branch = branch;
            this.predicateCount = predicateCount;
            this.branchCount = branchCount;
            this.branchPercentage = branchPercentage;
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
     * Formats a sorted list of integers as compact ranges.
     * e.g. [1,2,3,5,10,11] -> "1-3, 5, 10-11"
     */
    private String formatRanges(List<Integer> sortedLines) {
        if (sortedLines.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int rangeStart = sortedLines.get(0);
        int prev = rangeStart;
        for (int i = 1; i < sortedLines.size(); i++) {
            int cur = sortedLines.get(i);
            if (cur == prev + 1) {
                prev = cur;
            } else {
                if (sb.length() > 0) sb.append(", ");
                if (prev == rangeStart) sb.append(rangeStart);
                else sb.append(rangeStart).append("-").append(prev);
                rangeStart = cur;
                prev = cur;
            }
        }
        if (sb.length() > 0) sb.append(", ");
        if (prev == rangeStart) sb.append(rangeStart);
        else sb.append(rangeStart).append("-").append(prev);
        return sb.toString();
    }

    /**
     * Builds per-class coverage summary: maps className -> (allLines, coveredLines).
     */
    private Map<String, Object[]> buildClassCoverageMap() {
        // Use TreeMap for stable alphabetical ordering
        Map<String, Set<Integer>> allLinesPerClass = new TreeMap<>();
        Map<String, Set<Integer>> coveredLinesPerClass = new TreeMap<>();

        for (PredicateTarget pred : predicateTargets) {
            // Collect predicate line
            String cls = pred.getClassName();
            allLinesPerClass.computeIfAbsent(cls, k -> new HashSet<>()).add(pred.getPredicateLine());
            int predCount = lineCoverage.getInputCount(cls, pred.getPredicateLine());
            if (predCount > 0) {
                coveredLinesPerClass.computeIfAbsent(cls, k -> new HashSet<>()).add(pred.getPredicateLine());
            }
            // Collect branch lines
            for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                String bCls = branch.getClassName();
                allLinesPerClass.computeIfAbsent(bCls, k -> new HashSet<>()).add(branch.getLine());
                int bCount = lineCoverage.getInputCount(bCls, branch.getLine());
                if (bCount > 0) {
                    coveredLinesPerClass.computeIfAbsent(bCls, k -> new HashSet<>()).add(branch.getLine());
                }
            }
        }

        // Result: className -> [Set<Integer> allLines, Set<Integer> coveredLines]
        Map<String, Object[]> result = new TreeMap<>();
        for (String cls : allLinesPerClass.keySet()) {
            Set<Integer> all = allLinesPerClass.get(cls);
            Set<Integer> covered = coveredLinesPerClass.getOrDefault(cls, new HashSet<>());
            result.put(cls, new Object[]{all, covered});
        }
        return result;
    }

    /**
     * Prints a compact coverage summary grouped by class.
     */
    private void printCoarseGrainedCoverage() {
        System.out.println("=== COVERAGE SUMMARY (tracked predicate lines) ===");
        Map<String, Object[]> classMap = buildClassCoverageMap();
        for (Map.Entry<String, Object[]> entry : classMap.entrySet()) {
            String cls = entry.getKey();
            @SuppressWarnings("unchecked")
            Set<Integer> allLines = (Set<Integer>) entry.getValue()[0];
            @SuppressWarnings("unchecked")
            Set<Integer> coveredLines = (Set<Integer>) entry.getValue()[1];

            Set<Integer> uncoveredLines = new HashSet<>(allLines);
            uncoveredLines.removeAll(coveredLines);

            List<Integer> sortedCovered = new ArrayList<>(coveredLines);
            List<Integer> sortedUncovered = new ArrayList<>(uncoveredLines);
            Collections.sort(sortedCovered);
            Collections.sort(sortedUncovered);

            int total = allLines.size();
            int coveredCount = coveredLines.size();

            System.out.println(cls);
            System.out.printf("  Covered   (%d/%d): %s%n", coveredCount, total, formatRanges(sortedCovered));
            System.out.printf("  Uncovered  (%d/%d): %s%n", total - coveredCount, total, formatRanges(sortedUncovered));
        }
        System.out.println();
    }

    /**
     * Prints line coverage statistics to stdout.
     */
    private void printLineCoverageStats() {
        System.out.println();
        printCoarseGrainedCoverage();
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

        // Build coverage summary
        Map<String, Object[]> classMap = buildClassCoverageMap();
        List<Map<String, Object>> coverageSummary = new ArrayList<>();
        for (Map.Entry<String, Object[]> entry : classMap.entrySet()) {
            String cls = entry.getKey();
            @SuppressWarnings("unchecked")
            Set<Integer> allLines = (Set<Integer>) entry.getValue()[0];
            @SuppressWarnings("unchecked")
            Set<Integer> coveredLines = (Set<Integer>) entry.getValue()[1];

            Set<Integer> uncoveredLines = new HashSet<>(allLines);
            uncoveredLines.removeAll(coveredLines);

            List<Integer> sortedCovered = new ArrayList<>(coveredLines);
            List<Integer> sortedUncovered = new ArrayList<>(uncoveredLines);
            Collections.sort(sortedCovered);
            Collections.sort(sortedUncovered);

            Map<String, Object> summary = new HashMap<>();
            summary.put("class", cls);
            summary.put("coveredLines", formatRanges(sortedCovered));
            summary.put("uncoveredLines", formatRanges(sortedUncovered));
            summary.put("coveredCount", coveredLines.size());
            summary.put("totalTracked", allLines.size());
            coverageSummary.add(summary);
        }
        output.put("coverageSummary", coverageSummary);

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
