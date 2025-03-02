import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { InfoIcon, AlertTriangleIcon } from "lucide-react";
import ConfidenceScoreCard from "./reportSections/ConfidenceScoreCard";
import SecurityRisksCard from "./reportSections/SecurityRisksCard";

// Update types to match new format
type RepositoryReport = {
  repositoryName: string;
  timestamp: string;
  aiComponents: Array<{
    name: string;
    type: string;
    confidence: number;
    detectionMethod: 'import' | 'usage' | 'package' | 'configuration';
    locations: Array<{
      file: string;
      line: number;
      snippet: string;
      context: {
        before: string[];
        after: string[];
        scope?: string;
      }
    }>;
  }>;
  securityRisks: Array<{
    risk: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
    owaspCategory: {
      id: string;
      name: string;
      description: string;
    };
    relatedComponents: string[];
    evidence: Array<{
      file: string;
      line: number;
      snippet: string;
      context: {
        before: string[];
        after: string[];
        scope?: string;
      }
    }>;
    confidence: number;
  }>;
  callGraph: {
    nodes: string[];
    edges: Array<{
      from: string;
      to: string;
      type: string;
    }>;
  };
  summary: {
    totalAIUsage: number;
    risksByLevel: {
      high: number;
      medium: number;
      low: number;
    };
    topRisks: string[];
  };
};

interface ReportResultsProps {
  report: RepositoryReport | null;
}

export default function ReportResults({ report }: ReportResultsProps) {
  console.log('Report data:', report);

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

  console.log('AI Components:', report.aiComponents);
  console.log('Security Risks:', report.securityRisks);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Summary Statistics */}
        <div className="rounded-xl border bg-card text-card-foreground shadow">
          <div className="p-6">
            <div className="flex items-center space-x-2">
              <InfoIcon className="h-4 w-4 text-muted-foreground" />
              <h3 className="tracking-tight">Total AI Components</h3>
            </div>
            <div className="mt-2">
              <p className="text-2xl font-bold">{report.summary.totalAIUsage}</p>
            </div>
          </div>
        </div>

        {/* Risk Levels */}
        <div className="rounded-xl border bg-card text-card-foreground shadow">
          <div className="p-6">
            <div className="flex items-center space-x-2">
              <AlertTriangleIcon className="h-4 w-4 text-muted-foreground" />
              <h3 className="tracking-tight">Security Risks</h3>
            </div>
            <div className="mt-2 space-y-1">
              <p className="text-sm text-red-600">High: {report.summary.risksByLevel.high}</p>
              <p className="text-sm text-yellow-600">Medium: {report.summary.risksByLevel.medium}</p>
              <p className="text-sm text-green-600">Low: {report.summary.risksByLevel.low}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="grid gap-4 md:grid-cols-2">
        <SecurityRisksCard 
          risks={report.securityRisks}
          verifiedCodeReferences={[]}
          aiComponents={report.aiComponents}
        />
        <ConfidenceScoreCard components={report.aiComponents} />
      </div>
    </div>
  );
}
