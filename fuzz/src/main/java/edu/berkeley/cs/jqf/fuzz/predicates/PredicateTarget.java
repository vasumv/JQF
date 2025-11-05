package edu.berkeley.cs.jqf.fuzz.predicates;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a predicate and its branches from static analysis.
 * Parsed from the predicate dominance JSON file.
 */
public class PredicateTarget {
    private final String className;
    private final String methodName;
    private final int predicateLine;
    private final int dominanceScore;
    private final List<BranchTarget> branches;

    @JsonCreator
    public PredicateTarget(
            @JsonProperty("class") String className,
            @JsonProperty("method") String methodName,
            @JsonProperty("line") int predicateLine,
            @JsonProperty("dominanceScore") int dominanceScore,
            @JsonProperty("branches") List<BranchTarget> branches) {
        this.className = className;
        this.methodName = methodName;
        this.predicateLine = predicateLine;
        this.dominanceScore = dominanceScore;
        this.branches = branches != null ? branches : new ArrayList<>();
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public int getPredicateLine() {
        return predicateLine;
    }

    public int getDominanceScore() {
        return dominanceScore;
    }

    public List<BranchTarget> getBranches() {
        return branches;
    }

    /**
     * Represents a single branch from a predicate.
     */
    public static class BranchTarget {
        private final String className;
        private final int line;
        private final int dominance;

        @JsonCreator
        public BranchTarget(
                @JsonProperty("class") String className,
                @JsonProperty("line") int line,
                @JsonProperty("dominance") int dominance) {
            this.className = className;
            this.line = line;
            this.dominance = dominance;
        }

        public String getClassName() {
            return className;
        }

        public int getLine() {
            return line;
        }

        public int getDominance() {
            return dominance;
        }
    }

    /**
     * Wrapper class for JSON deserialization.
     */
    private static class PredicatesWrapper {
        @JsonProperty("predicates")
        private List<PredicateTarget> predicates;

        public List<PredicateTarget> getPredicates() {
            return predicates != null ? predicates : new ArrayList<>();
        }
    }

    /**
     * Parse predicates from JSON file using Jackson.
     * Returns predicates sorted by dominance score (highest first).
     *
     * Format expected:
     * {
     *   "predicates": [
     *     {
     *       "class": "com.example.MyClass",
     *       "method": "myMethod",
     *       "line": 42,
     *       "dominanceScore": 15,
     *       "branches": [
     *         { "class": "com.example.MyClass", "line": 45, "dominance": 3 },
     *         { "class": "com.example.MyClass", "line": 50, "dominance": 10 }
     *       ]
     *     }
     *   ]
     * }
     */
    public static List<PredicateTarget> fromJson(String jsonPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        PredicatesWrapper wrapper = mapper.readValue(new File(jsonPath), PredicatesWrapper.class);
        List<PredicateTarget> predicates = wrapper.getPredicates();

        // Sort by dominance score (highest first)
        predicates.sort((p1, p2) -> Integer.compare(p2.getDominanceScore(), p1.getDominanceScore()));

        return predicates;
    }

    @Override
    public String toString() {
        return String.format("PredicateTarget{class=%s, method=%s, line=%d, dominance=%d, branches=%d}",
                           className, methodName, predicateLine, dominanceScore, branches.size());
    }
}
