package edu.berkeley.cs.jqf.fuzz.predicates;

import edu.berkeley.cs.jqf.instrument.tracing.events.AllocEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.BranchEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.CallEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.ReadEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.ReturnEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEventVisitor;

import java.util.*;

/**
 * Tracks line-level coverage for specific lines of interest.
 * Counts how many unique inputs hit each tracked line.
 */
public class LineCoverage implements TraceEventVisitor {

    /** Current input ID being executed */
    private int currentInputId = 0;

    /** Map: (className, lineNumber) -> Set of input IDs that hit this line */
    private final Map<String, Map<Integer, Set<Integer>>> lineInputSets;

    /** Set of lines to track (className, lineNumber) */
    private final Set<LineLocation> trackedLines;

    /**
     * Creates a new LineCoverage tracker.
     *
     * @param predicateTargets the predicate targets from static analysis
     */
    public LineCoverage(List<PredicateTarget> predicateTargets) {
        this.lineInputSets = new HashMap<>();
        this.trackedLines = new HashSet<>();

        // Extract all lines to track from predicate targets
        for (PredicateTarget pred : predicateTargets) {
            // Track the predicate line itself
            trackedLines.add(new LineLocation(pred.getClassName(), pred.getPredicateLine()));

            // Track each branch line
            for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                trackedLines.add(new LineLocation(branch.getClassName(), branch.getLine()));
            }

            // Debug logging for TreeSingleSourcePathsImpl line 135
            if (pred.getClassName().equals("org.jgrapht.alg.shortestpath.TreeSingleSourcePathsImpl") &&
                pred.getPredicateLine() == 135) {
                System.err.println("[DEBUG] Tracking predicate at " + pred.getClassName() + ":" + pred.getPredicateLine());
                for (PredicateTarget.BranchTarget branch : pred.getBranches()) {
                    System.err.println("[DEBUG]   Branch at " + branch.getClassName() + ":" + branch.getLine());
                }
            }
        }
    }

    /**
     * Sets the ID of the current input being executed.
     * Should be called before each new input execution.
     *
     * @param inputId the unique ID for this input
     */
    public void setCurrentInputId(int inputId) {
        this.currentInputId = inputId;
    }

    /**
     * Handles a trace event and updates line coverage if the line is tracked.
     *
     * @param event the trace event
     */
    public void handleEvent(TraceEvent event) {
        event.applyVisitor(this);
    }

    @Override
    public void visitBranchEvent(BranchEvent event) {
        recordLineHit(event);
    }

    @Override
    public void visitCallEvent(CallEvent event) {
        recordLineHit(event);
    }

    @Override
    public void visitAllocEvent(AllocEvent event) {
        recordLineHit(event);
    }

    @Override
    public void visitReadEvent(ReadEvent event) {
        recordLineHit(event);
    }

    @Override
    public void visitReturnEvent(ReturnEvent event) {
        recordLineHit(event);
    }

    /**
     * Records that the current input hit a specific line.
     */
    private void recordLineHit(TraceEvent event) {
        String className = event.getContainingClass();
        int lineNumber = event.getLineNumber();

        // Convert to dot format for consistency
        String classNameDot = className.replace("/", ".");

        // Debug logging for TreeSingleSourcePathsImpl - show ALL events to understand line mappings
        if (classNameDot.equals("org.jgrapht.alg.shortestpath.TreeSingleSourcePathsImpl") && currentInputId <= 5) {
            System.err.println("[DEBUG] Event: " + event.getClass().getSimpleName() +
                             " at " + classNameDot + ":" + lineNumber +
                             " inputId=" + currentInputId +
                             " tracked=" + isTrackedLine(classNameDot, lineNumber));
        }

        // Only track if this line is in our targets
        if (lineNumber > 0 && isTrackedLine(classNameDot, lineNumber)) {
            lineInputSets
                .computeIfAbsent(classNameDot, k -> new HashMap<>())
                .computeIfAbsent(lineNumber, k -> new HashSet<>())
                .add(currentInputId);
        }
    }

    /**
     * Checks if a line should be tracked.
     * Expects className in dot format (e.g., org.jgrapht.Graphs)
     */
    private boolean isTrackedLine(String className, int lineNumber) {
        return trackedLines.contains(new LineLocation(className, lineNumber));
    }

    /**
     * Gets the number of unique inputs that hit a specific line.
     *
     * @param className the class name
     * @param lineNumber the line number
     * @return the number of unique inputs that hit this line
     */
    public int getInputCount(String className, int lineNumber) {
        return lineInputSets
            .getOrDefault(className, Collections.emptyMap())
            .getOrDefault(lineNumber, Collections.emptySet())
            .size();
    }

    /**
     * Gets the set of input IDs that hit a specific line.
     *
     * @param className the class name
     * @param lineNumber the line number
     * @return the set of input IDs
     */
    public Set<Integer> getInputsForLine(String className, int lineNumber) {
        return lineInputSets
            .getOrDefault(className, Collections.emptyMap())
            .getOrDefault(lineNumber, Collections.emptySet());
    }

    /**
     * Gets coverage statistics for all tracked lines.
     *
     * @return map of (className, lineNumber) to input count
     */
    public Map<String, Map<Integer, Integer>> getCoverageStats() {
        Map<String, Map<Integer, Integer>> stats = new HashMap<>();

        for (Map.Entry<String, Map<Integer, Set<Integer>>> classEntry : lineInputSets.entrySet()) {
            String className = classEntry.getKey();
            Map<Integer, Integer> lineCounts = new HashMap<>();

            for (Map.Entry<Integer, Set<Integer>> lineEntry : classEntry.getValue().entrySet()) {
                lineCounts.put(lineEntry.getKey(), lineEntry.getValue().size());
            }

            stats.put(className, lineCounts);
        }

        return stats;
    }

    /**
     * Represents a line location (class + line number).
     */
    private static class LineLocation {
        private final String className;
        private final int lineNumber;

        LineLocation(String className, int lineNumber) {
            this.className = className;
            this.lineNumber = lineNumber;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof LineLocation)) return false;
            LineLocation other = (LineLocation) obj;
            return lineNumber == other.lineNumber &&
                   Objects.equals(className, other.className);
        }

        @Override
        public int hashCode() {
            return Objects.hash(className, lineNumber);
        }

        @Override
        public String toString() {
            return className + ":" + lineNumber;
        }
    }
}
