
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
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
  }[];
  code_references: {
    file: string;
    line: number;
    snippet: string;
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

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
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

      {/* Security Risks Section */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Security Risks</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {report.security_risks.map((risk, index) => (
              <div key={index} className="p-3 rounded-md bg-gray-50">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium">{risk.risk}</span>
                  <Badge className={getSeverityColor(risk.severity)}>
                    {risk.severity}
                  </Badge>
                </div>
                <p className="text-sm text-gray-600">{risk.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Code References Section */}
      {report.code_references.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xl">Code References</CardTitle>
          </CardHeader>
          <CardContent>
            <Accordion type="single" collapsible className="w-full">
              {report.code_references.map((reference, index) => (
                <AccordionItem key={index} value={`item-${index}`}>
                  <AccordionTrigger className="hover:no-underline">
                    <div className="flex items-center text-left">
                      <span className="font-medium">{reference.file}</span>
                      <span className="ml-2 text-sm text-gray-500">Line {reference.line}</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="bg-gray-100 p-3 rounded-md font-mono text-sm overflow-x-auto">
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
