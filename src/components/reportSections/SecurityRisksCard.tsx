import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, AlertTriangle, Info } from "lucide-react";
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from "@/components/ui/accordion";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger
} from "@/components/ui/tooltip";
import { SecurityRisk, CodeReference, AIComponent } from "@/types/reportTypes";
import { getSeverityColor, getOwaspBadgeColor } from "@/utils/styleUtils";
import { getRelatedCodeReferences, getRelatedAIComponents } from "@/utils/riskAnalysisUtils";
import CodeReferencesList from "./CodeReferencesList";

interface SecurityRisksCardProps {
  risks: Array<{
    risk: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
    owaspCategory: {
      id: string;
      name: string;
      description: string;
    };
    evidence: Array<{
      file: string;
      line: number;
      snippet: string;
    }>;
  }>;
  verifiedCodeReferences: CodeReference[];
  aiComponents: AIComponent[];
}

const SecurityRisksCard = ({ 
  risks, 
  verifiedCodeReferences,
  aiComponents
}: SecurityRisksCardProps) => {
  // Add debug logging to see what security risks we're receiving
  console.log("Security risks in SecurityRisksCard:", JSON.stringify(risks, null, 2));
  
  // Filter to ensure we only process valid security risks
  // Also deduplicate risks by name to prevent duplicates
  const processedRisks = new Map<string, SecurityRisk>();
  
  risks.forEach(risk => {
    if (!risk || typeof risk !== 'object') {
      console.log("Invalid risk object:", risk);
      return;
    }
    
    // Must have either risk or risk_name
    const riskName = risk.risk || risk.risk_name;
    if (!riskName) {
      console.log("Risk without name:", risk);
      return;
    }
    
    // If this risk is already in our map, merge related_code_references
    if (processedRisks.has(riskName)) {
      const existingRisk = processedRisks.get(riskName)!;
      if (risk.related_code_references && existingRisk.related_code_references) {
        existingRisk.related_code_references = [
          ...new Set([
            ...existingRisk.related_code_references,
            ...risk.related_code_references
          ])
        ];
      } else if (risk.related_code_references) {
        existingRisk.related_code_references = [...risk.related_code_references];
      }
    } else {
      // Add new risk to the map
      processedRisks.set(riskName, risk);
    }
  });
  
  // Convert map back to array
  const validSecurityRisks = Array.from(processedRisks.values());

  // Explicitly log if we have the "Hardcoded System Prompts" risk
  const systemPromptRisk = validSecurityRisks.find(risk => 
    (risk.risk || '').toLowerCase().includes('hardcoded system prompt') || 
    (risk.risk || '').toLowerCase().includes('system prompt leak')
  );
  
  console.log("System Prompt risk found:", systemPromptRisk ? 'Yes' : 'No');
  if (systemPromptRisk) {
    // Check if there are any prompt definition references
    const promptRefs = verifiedCodeReferences.filter(ref => 
      ref.type === 'prompt_definition' || 
      ref.snippet.toLowerCase().includes('system_prompt') ||
      ref.snippet.toLowerCase().includes('system prompt')
    );
    console.log("Prompt definition references:", promptRefs.length);
  }
  
  // Group risks by OWASP category for better organization
  const risksByOwaspCategory = validSecurityRisks.reduce((acc, risk) => {
    if (risk.owasp_category?.id) {
      const categoryId = risk.owasp_category.id;
      if (!acc[categoryId]) {
        acc[categoryId] = [];
      }
      acc[categoryId].push(risk);
    } else {
      // Handle risks without OWASP category
      if (!acc['uncategorized']) {
        acc['uncategorized'] = [];
      }
      acc['uncategorized'].push(risk);
    }
    return acc;
  }, {} as Record<string, SecurityRisk[]>);
  
  console.log("Valid security risks count after deduplication:", validSecurityRisks.length);
  console.log("Risks grouped by OWASP category:", Object.keys(risksByOwaspCategory));
  
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-red-500" />
          Security Risks
        </CardTitle>
      </CardHeader>
      <CardContent>
        {validSecurityRisks.length > 0 ? (
          <Accordion type="single" collapsible className="w-full">
            {validSecurityRisks.map((risk, index) => {
              // Get the risk name from either field
              const riskName = risk.risk || risk.risk_name || "Unknown Risk";
              
              // Get code references related to this specific risk using the IDs
              const relatedReferences = getRelatedCodeReferences(risk, verifiedCodeReferences);
              // Get AI components potentially related to this risk
              const relatedComponents = getRelatedAIComponents(risk, aiComponents);
              
              return (
                <AccordionItem key={index} value={`risk-${index}`}>
                  <AccordionTrigger className="hover:no-underline py-3">
                    <div className="flex items-center justify-between w-full pr-4">
                      <span className="font-medium text-left">{riskName}</span>
                      <div className="flex items-center space-x-2">
                        {risk.owasp_category && (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger>
                                <Badge className={`${getOwaspBadgeColor(risk.owasp_category.id)} flex items-center`}>
                                  <ShieldAlert className="h-3 w-3 mr-1" /> 
                                  {risk.owasp_category.id}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent side="left" className="max-w-sm">
                                <div className="max-w-xs">
                                  <p className="font-bold">{risk.owasp_category.name}</p>
                                  <p className="text-xs">{risk.owasp_category.description}</p>
                                </div>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        )}
                        <Badge className={`${getSeverityColor(risk.severity)}`}>
                          {risk.severity}
                        </Badge>
                      </div>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-4 pt-2">
                      <p className="text-gray-600">{risk.description}</p>
                      
                      {/* OWASP Category Information */}
                      {risk.owasp_category && (
                        <div className="bg-gray-50 p-3 rounded-md border border-gray-200 text-sm space-y-1">
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4 text-gray-700" />
                            <h4 className="font-semibold">OWASP LLM Top 10 Classification:</h4>
                          </div>
                          <div className="pl-6">
                            <p className="font-medium">{risk.owasp_category.id}: {risk.owasp_category.name}</p>
                            <p className="text-gray-600 text-sm">{risk.owasp_category.description}</p>
                          </div>
                        </div>
                      )}
                      
                      {/* Related AI Components Section */}
                      {relatedComponents.length > 0 && (
                        <div className="mt-4">
                          <h4 className="text-sm font-medium text-gray-700 mb-2">Related AI Components:</h4>
                          <div className="space-y-2">
                            {relatedComponents.map((component, compIndex) => (
                              <div key={compIndex} className="p-2 bg-gray-50 rounded border border-gray-100 text-sm">
                                <div className="font-medium">{component.name}</div>
                                <div className="text-xs text-gray-500">{component.type}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {/* Code Evidence for this risk */}
                      <div className="mt-4">
                        <h4 className="text-sm font-medium text-gray-700 mb-2">Evidence in Code:</h4>
                        {relatedReferences.length > 0 ? (
                          <CodeReferencesList 
                            references={relatedReferences} 
                            riskIndex={index} 
                          />
                        ) : (
                          <div className="text-sm text-gray-500 italic flex items-center gap-2 p-2 bg-gray-50 rounded border border-gray-100">
                            <Info className="h-4 w-4 text-blue-500" />
                            <p>No specific code references linked to this risk.</p>
                          </div>
                        )}
                      </div>

                      {/* Impact Rating */}
                      <div className="mt-4 p-3 bg-gray-50 rounded-md border border-gray-200">
                        <h4 className="text-sm font-medium text-gray-700 mb-1">Impact Assessment</h4>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`h-4 w-4 ${getSeverityIconColor(risk.severity)}`} />
                          <span className="text-sm font-medium">{getSeverityDescription(risk.severity)}</span>
                        </div>
                      </div>
                    </div>
                  </AccordionContent>
                </AccordionItem>
              );
            })}
          </Accordion>
        ) : (
          <div className="p-4 text-center text-gray-500">
            No security risks detected in this repository.
          </div>
        )}

        {/* OWASP Reference Note */}
        <div className="mt-6 p-3 rounded-md bg-blue-50 border border-blue-100">
          <div className="flex items-start gap-2">
            <ShieldAlert className="h-4 w-4 text-blue-500 mt-0.5" />
            <div>
              <h4 className="text-sm font-medium text-blue-700">About OWASP LLM Top 10</h4>
              <p className="text-xs text-blue-600 mt-1">
                Security risks are categorized according to the OWASP LLM Top 10, a standard awareness document for 
                developers and web application security. It represents a broad consensus about the most critical 
                security risks to LLM applications.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Helper functions for risk severity
function getSeverityIconColor(severity: string): string {
  const lowerSeverity = severity.toLowerCase();
  if (lowerSeverity === 'high' || lowerSeverity === 'critical') return 'text-red-500';
  if (lowerSeverity === 'medium') return 'text-amber-500';
  if (lowerSeverity === 'low') return 'text-blue-500';
  return 'text-gray-500';
}

function getSeverityDescription(severity: string): string {
  const lowerSeverity = severity.toLowerCase();
  if (lowerSeverity === 'high' || lowerSeverity === 'critical') 
    return 'High Impact - Requires immediate attention and mitigation';
  if (lowerSeverity === 'medium') 
    return 'Medium Impact - Should be addressed in the near term';
  if (lowerSeverity === 'low') 
    return 'Low Impact - Address as part of regular security maintenance';
  return 'Informational - General security consideration';
}

export default SecurityRisksCard;
