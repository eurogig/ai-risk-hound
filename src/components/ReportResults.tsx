
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { InfoIcon, AlertTriangleIcon } from "lucide-react";
import { RepositoryReport } from "@/types/reportTypes";
import { enhanceCodeReferences, getUnrelatedCodeReferences } from "@/utils/riskAnalysisUtils";
import ConfidenceScoreCard from "./reportSections/ConfidenceScoreCard";
import SecurityRisksCard from "./reportSections/SecurityRisksCard";
import AIComponentsCard from "./reportSections/AIComponentsCard";
import AdditionalCodeReferencesCard from "./reportSections/AdditionalCodeReferencesCard";
import RemediationSuggestionsCard from "./reportSections/RemediationSuggestionsCard";

interface ReportResultsProps {
  report: RepositoryReport;
}

const ReportResults = ({ report }: ReportResultsProps) => {
  // Add debug logging
  console.log("Report received in ReportResults:", report);
  
  // Check if report is valid
  if (!report) {
    return (
      <Alert variant="destructive">
        <AlertTriangleIcon className="h-4 w-4" />
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>
          No report data received. Please try again with a different repository.
        </AlertDescription>
      </Alert>
    );
  }
  
  // Check if required properties exist
  if (!report.code_references || !report.security_risks || !report.ai_components_detected) {
    console.error("Missing required report properties:", report);
    return (
      <Alert variant="destructive">
        <AlertTriangleIcon className="h-4 w-4" />
        <AlertTitle>Invalid Report Format</AlertTitle>
        <AlertDescription>
          <p>The report is missing required properties. Debug information:</p>
          <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto">
            {JSON.stringify({
              has_code_references: !!report.code_references,
              has_security_risks: !!report.security_risks,
              has_ai_components: !!report.ai_components_detected,
              confidence_score: report.confidence_score,
              remediation_count: report.remediation_suggestions?.length || 0
            }, null, 2)}
          </pre>
        </AlertDescription>
      </Alert>
    );
  }
  
  // Extra validation steps for required arrays
  if (!Array.isArray(report.code_references) || !Array.isArray(report.security_risks) || !Array.isArray(report.ai_components_detected)) {
    console.error("Report arrays are not valid arrays:", report);
    return (
      <Alert variant="destructive">
        <AlertTriangleIcon className="h-4 w-4" />
        <AlertTitle>Invalid Report Data</AlertTitle>
        <AlertDescription>
          <p>The report contains invalid data structures. Expected arrays but received:</p>
          <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto">
            {JSON.stringify({
              code_references_type: typeof report.code_references,
              security_risks_type: typeof report.security_risks,
              ai_components_type: typeof report.ai_components_detected
            }, null, 2)}
          </pre>
        </AlertDescription>
      </Alert>
    );
  }
  
  // Filter out unverified code references
  const verifiedCodeReferences = report.code_references.filter(ref => ref && ref.verified === true);
  console.log("Verified code references:", verifiedCodeReferences.length);
  
  try {
    // Enhance the report by filling in missing connections and detecting hardcoded system prompts
    const enhancedSecurityRisks = enhanceCodeReferences(
      report.security_risks,
      verifiedCodeReferences,
      report.confidence_score
    );
    
    // Get code references that aren't related to any security risks
    const unrelatedCodeReferences = getUnrelatedCodeReferences(
      enhancedSecurityRisks,
      verifiedCodeReferences
    );

    // Check remediation suggestions for validity before rendering
    const validRemediationSuggestions = Array.isArray(report.remediation_suggestions) 
      ? report.remediation_suggestions
          .filter(suggestion => 
            suggestion !== null && 
            typeof suggestion === 'object'
          )
          .filter(suggestion => {
            // This separate filter ensures we don't access properties of null objects
            if (suggestion && 'suggestion' in suggestion && typeof suggestion.suggestion === 'string') {
              return true;
            }
            return false;
          })
          .map(suggestion => suggestion?.suggestion || '')
          .filter(suggestionText => suggestionText !== '')
      : [];
    
    console.log("Valid remediation suggestions:", validRemediationSuggestions.length);

    return (
      <div className="space-y-6 animate-in fade-in duration-500">
        <Alert className="bg-yellow-50 border-yellow-200">
          <InfoIcon className="h-4 w-4 text-yellow-600" />
          <AlertDescription className="text-yellow-800">
            This analysis is powered by AI and only displays confirmed findings. The report may not catch all AI components or security risks.
          </AlertDescription>
        </Alert>
        
        {/* Overall Score Card */}
        <ConfidenceScoreCard confidenceScore={report.confidence_score} />

        {/* Security Risks Section */}
        <SecurityRisksCard 
          securityRisks={enhancedSecurityRisks} 
          verifiedCodeReferences={verifiedCodeReferences}
          aiComponents={report.ai_components_detected}
        />

        {/* AI Components Section */}
        <AIComponentsCard components={report.ai_components_detected} />

        {/* Additional Code References Section */}
        <AdditionalCodeReferencesCard references={unrelatedCodeReferences} />

        {/* Remediation Suggestions - Only show if valid suggestions exist */}
        {validRemediationSuggestions.length > 0 && (
          <RemediationSuggestionsCard suggestions={validRemediationSuggestions} />
        )}
      </div>
    );
  } catch (error) {
    console.error("Error processing report data:", error);
    return (
      <Alert variant="destructive">
        <AlertTriangleIcon className="h-4 w-4" />
        <AlertTitle>Processing Error</AlertTitle>
        <AlertDescription>
          <p>An error occurred while processing the report: {String(error)}</p>
          <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto">
            Report data: {JSON.stringify({
              code_references_count: report.code_references?.length || 0,
              security_risks_count: report.security_risks?.length || 0,
              ai_components_count: report.ai_components_detected?.length || 0,
              confidence_score: report.confidence_score
            }, null, 2)}
          </pre>
        </AlertDescription>
      </Alert>
    );
  }
};

export default ReportResults;
