
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { InfoIcon } from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface RepositoryReport {
  ai_components_detected: {
    name: string;
    type: string;
    confidence: number;
  }[];
  security_risks: {
    risk: string;
    severity: string;
    description: string;
    related_code_references: string[]; // IDs of related code references
  }[];
  code_references: {
    id: string; // Unique ID for each reference
    file: string;
    line: number;
    snippet: string;
    verified: boolean;
    relatedRisks?: string[]; // Risk names this reference is related to
  }[];
  confidence_score: number;
  remediation_suggestions: string[];
}

interface ReportResultsProps {
  report: RepositoryReport;
}

const ReportResults = ({ report }: ReportResultsProps) => {
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500";
      case "high":
        return "bg-orange-500";
      case "medium":
        return "bg-yellow-500";
      case "low":
        return "bg-blue-500";
      case "info":
        return "bg-gray-500";
      default:
        return "bg-gray-500";
    }
  };

  // Filter out unverified code references
  const verifiedCodeReferences = report.code_references.filter(ref => ref.verified === true);

  // Get the code references for a specific security risk using the IDs
  const getRelatedCodeReferences = (risk: { risk: string; related_code_references: string[] }) => {
    return verifiedCodeReferences.filter(ref => 
      risk.related_code_references && risk.related_code_references.includes(ref.id)
    );
  };

  // Get code references that aren't related to any security risks
  const getUnrelatedCodeReferences = () => {
    const allRiskRefIds = new Set(
      report.security_risks.flatMap(risk => risk.related_code_references || [])
    );
    
    return verifiedCodeReferences.filter(ref => !allRiskRefIds.has(ref.id));
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <Alert className="bg-yellow-50 border-yellow-200">
        <InfoIcon className="h-4 w-4 text-yellow-600" />
        <AlertDescription className="text-yellow-800">
          This analysis is powered by AI and only displays confirmed findings. The report may not catch all AI components or security risks.
        </AlertDescription>
      </Alert>
      
      {/* Overall Score Card */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">AI Confidence Score</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">How likely this repo contains AI components</span>
              <span className="font-medium">{Math.round(report.confidence_score * 100)}%</span>
            </div>
            <Progress value={report.confidence_score * 100} 
              className={`h-2 ${report.confidence_score > 0.7 ? 'bg-red-100' : 'bg-gray-100'}`} 
            />
            <div className="pt-2">
              {report.confidence_score > 0.8 ? (
                <Badge className="bg-red-500">High AI Usage</Badge>
              ) : report.confidence_score > 0.4 ? (
                <Badge className="bg-yellow-500">Moderate AI Usage</Badge>
              ) : (
                <Badge className="bg-green-500">Low/No AI Usage</Badge>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* AI Components Section */}
      {report.ai_components_detected.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xl">AI Components Detected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {report.ai_components_detected.map((component, index) => (
                <div key={index} className="flex justify-between items-center p-3 rounded-md bg-gray-50">
                  <div>
                    <div className="font-medium">{component.name}</div>
                    <div className="text-sm text-gray-500">{component.type}</div>
                  </div>
                  <Badge variant="outline" className="ml-auto">
                    {Math.round(component.confidence * 100)}% confidence
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Risks Section with Connected Code References */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Security Risks</CardTitle>
        </CardHeader>
        <CardContent>
          {report.security_risks.length > 0 ? (
            <div className="space-y-6">
              {report.security_risks.map((risk, index) => {
                // Get code references related to this specific risk using the IDs
                const relatedReferences = getRelatedCodeReferences(risk);
                
                return (
                  <div key={index} className="space-y-3">
                    <div className="p-3 rounded-md bg-gray-50">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium">{risk.risk}</span>
                        <Badge className={getSeverityColor(risk.severity)}>
                          {risk.severity}
                        </Badge>
                      </div>
                      <p className="text-sm text-gray-600">{risk.description}</p>
                    </div>
                    
                    {/* Code Evidence for this risk - only shown if there are relevant references */}
                    {relatedReferences.length > 0 && (
                      <div className="ml-4 border-l-2 border-gray-200 pl-4">
                        <p className="text-sm text-gray-500 mb-2">Evidence found in code:</p>
                        <Accordion type="single" collapsible className="w-full">
                          {relatedReferences.map((reference, refIndex) => (
                            <AccordionItem key={refIndex} value={`risk-${index}-ref-${refIndex}`}>
                              <AccordionTrigger className="hover:no-underline text-sm">
                                <div className="flex items-center text-left">
                                  <span className="font-medium">{reference.file}</span>
                                  <span className="ml-2 text-sm text-gray-500">Line {reference.line}</span>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent>
                                <div className="p-3 rounded-md font-mono text-sm overflow-x-auto bg-gray-100">
                                  {reference.snippet}
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                        </Accordion>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-4 text-center text-gray-500">
              No security risks detected in this repository.
            </div>
          )}
        </CardContent>
      </Card>

      {/* Additional Code References Section (showing references not connected to security risks) */}
      {getUnrelatedCodeReferences().length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xl">AI References in Code</CardTitle>
          </CardHeader>
          <CardContent>
            <Accordion type="single" collapsible className="w-full">
              {getUnrelatedCodeReferences().map((reference, index) => (
                <AccordionItem key={index} value={`item-${index}`}>
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center text-left">
                      <span className="font-medium">{reference.file}</span>
                      <span className="ml-2 text-sm text-gray-500">Line {reference.line}</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="p-3 rounded-md font-mono text-sm overflow-x-auto bg-gray-100">
                      {reference.snippet}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </CardContent>
        </Card>
      )}

      {/* Remediation Suggestions */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Remediation Suggestions</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2 list-disc pl-5">
            {report.remediation_suggestions.map((suggestion, index) => (
              <li key={index} className="text-gray-700">{suggestion}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
};

export default ReportResults;
