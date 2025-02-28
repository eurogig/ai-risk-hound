
import { Alert, AlertDescription } from "@/components/ui/alert";
import { InfoIcon } from "lucide-react";
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
  // Filter out unverified code references
  const verifiedCodeReferences = report.code_references.filter(ref => ref.verified === true);
  
  // Enhance the report by filling in missing connections
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

      {/* Remediation Suggestions */}
      <RemediationSuggestionsCard suggestions={report.remediation_suggestions} />
    </div>
  );
};

export default ReportResults;
