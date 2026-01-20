#!/usr/bin/env node

/**
 * Test Report Generator
 * 
 * Generates TEST_REPORT.md mapping features to their tests
 * and highlighting coverage gaps.
 * 
 * Usage: npm run test:report
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const SRC_DIR = path.join(ROOT_DIR, 'src');
const FEATURES_DIR = path.join(SRC_DIR, 'features');

// Security scenarios that should be tested
const SECURITY_SCENARIOS = [
    { code: '401', description: 'Unauthorized' },
    { code: '403', description: 'Forbidden' },
    { code: '429', description: 'Rate Limited' },
];

/**
 * Find all feature directories
 */
function getFeatures() {
    if (!fs.existsSync(FEATURES_DIR)) {
        return [];
    }

    return fs.readdirSync(FEATURES_DIR, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name);
}

/**
 * Find test files for a feature
 */
function getTestFiles(featureName) {
    const featurePath = path.join(FEATURES_DIR, featureName);
    const testFiles = [];

    function searchDir(dir) {
        if (!fs.existsSync(dir)) return;

        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                searchDir(fullPath);
            } else if (entry.name.match(/\.(test|spec)\.(ts|tsx)$/)) {
                testFiles.push(path.relative(ROOT_DIR, fullPath));
            }
        }
    }

    searchDir(featurePath);
    return testFiles;
}

/**
 * Check if test file contains security scenario tests
 */
function checkSecurityCoverage(testFilePath) {
    const fullPath = path.join(ROOT_DIR, testFilePath);
    if (!fs.existsSync(fullPath)) return {};

    const content = fs.readFileSync(fullPath, 'utf-8');

    return SECURITY_SCENARIOS.reduce((acc, scenario) => {
        // Check for common patterns like "401", "status: 401", "Unauthorized"
        const patterns = [
            scenario.code,
            scenario.description.toLowerCase(),
        ];

        acc[scenario.code] = patterns.some(pattern =>
            content.toLowerCase().includes(pattern)
        );

        return acc;
    }, {});
}

/**
 * Generate the report
 */
function generateReport() {
    const timestamp = new Date().toISOString();
    const features = getFeatures();

    let report = `# 🧪 Test Report

> Generated: ${timestamp}

## Feature Coverage

| Feature | Tests | Status |
|---------|-------|--------|
`;

    const featureDetails = [];

    for (const feature of features) {
        const testFiles = getTestFiles(feature);
        const hasTests = testFiles.length > 0;

        report += `| \`${feature}\` | ${testFiles.length} | ${hasTests ? '✅' : '🔴 [HIGH RISK]'} |\n`;

        featureDetails.push({
            name: feature,
            testFiles,
            hasTests,
        });
    }

    if (features.length === 0) {
        report += `| *(no features yet)* | - | - |\n`;
    }

    // Security Coverage Section
    report += `
## Security Scenario Coverage

| Feature | 401 | 403 | 429 |
|---------|-----|-----|-----|
`;

    for (const feature of featureDetails) {
        if (!feature.hasTests) {
            report += `| \`${feature.name}\` | ❌ | ❌ | ❌ |\n`;
            continue;
        }

        const allCoverage = { '401': false, '403': false, '429': false };

        for (const testFile of feature.testFiles) {
            const coverage = checkSecurityCoverage(testFile);
            Object.keys(coverage).forEach(key => {
                if (coverage[key]) allCoverage[key] = true;
            });
        }

        report += `| \`${feature.name}\` | ${allCoverage['401'] ? '✅' : '❌'} | ${allCoverage['403'] ? '✅' : '❌'} | ${allCoverage['429'] ? '✅' : '❌'} |\n`;
    }

    if (features.length === 0) {
        report += `| *(no features yet)* | - | - | - |\n`;
    }

    // Test File Mapping
    report += `
## Test File Mapping

`;

    for (const feature of featureDetails) {
        report += `### ${feature.name}\n\n`;

        if (feature.testFiles.length === 0) {
            report += `> ⚠️ **[HIGH RISK]** No tests found for this feature\n\n`;
        } else {
            for (const testFile of feature.testFiles) {
                report += `- \`${testFile}\`\n`;
            }
            report += '\n';
        }
    }

    if (features.length === 0) {
        report += `*No features created yet. Add features to \`src/features/\` to track their test coverage.*\n`;
    }

    // Summary
    const totalFeatures = features.length;
    const testedFeatures = featureDetails.filter(f => f.hasTests).length;
    const coveragePercent = totalFeatures > 0
        ? Math.round((testedFeatures / totalFeatures) * 100)
        : 0;

    report += `
---

## Summary

- **Features:** ${totalFeatures}
- **Tested:** ${testedFeatures}
- **Coverage:** ${coveragePercent}%

`;

    if (testedFeatures < totalFeatures) {
        report += `### ⚠️ Action Required

The following features need tests:

`;
        for (const feature of featureDetails.filter(f => !f.hasTests)) {
            report += `- \`${feature.name}\`\n`;
        }
    }

    return report;
}

// Main execution
const report = generateReport();
const outputPath = path.join(ROOT_DIR, 'TEST_REPORT.md');
fs.writeFileSync(outputPath, report);

console.log(`✅ Test report generated: ${outputPath}`);
