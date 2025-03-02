import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
  verifiedCodeReferences = [],
  aiComponents = []
}: SecurityRisksCardProps) => {
  if (!risks || risks.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-green-500" />
            Security Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="p-4 text-center text-gray-500">
            No security risks detected in this repository.
          </div>
        </CardContent>
      </Card>
    );
  }

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
  
  // Group risks by OWASP category
  const risksByCategory = risks.reduce((acc, risk) => {
    const category = risk.owaspCategory?.id || 'uncategorized';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(risk);
    return acc;
  }, {} as Record<string, SecurityRisk[]>);
  
  console.log("Valid security risks count after deduplication:", validSecurityRisks.length);
  console.log("Risks grouped by OWASP category:", Object.keys(risksByCategory));
  
  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Analysis</CardTitle>
        <CardDescription>
          Grouped by OWASP LLM Top 10 Categories
        </CardDescription>
      </CardHeader>
      <CardContent>
        {Object.entries(risksByCategory).map(([category, categoryRisks]) => (
          <div key={category} className="mb-6">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              {category !== 'uncategorized' ? 
                `${category}: ${categoryRisks[0]?.owaspCategory?.name}` : 
                'Other Risks'}
            </h3>
            <p className="text-sm text-gray-500 mb-2">
              {categoryRisks[0]?.owaspCategory?.description || 'Miscellaneous security concerns'}
            </p>
            <Accordion type="single" collapsible>
              {categoryRisks.map((risk, idx) => {
                // Get the risk name from either field
                const riskName = risk.risk || risk.risk_name || "Unknown Risk";
                
                // Get code references related to this specific risk using the IDs
                const relatedReferences = getRelatedCodeReferences(risk, verifiedCodeReferences);
                // Get AI components potentially related to this risk
                const relatedComponents = getRelatedAIComponents(risk, aiComponents);
                
                return (
                  <AccordionItem key={idx} value={`risk-${idx}`}>
                    <AccordionTrigger className="hover:no-underline py-3">
                      <div className="flex items-center justify-between w-full pr-4">
                        <span className="font-medium text-left">{riskName}</span>
                        <div className="flex items-center space-x-2">
                          {risk.owaspCategory && (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger>
                                  <Badge className={`${getOwaspBadgeColor(risk.owaspCategory?.id || 'uncategorized')} flex items-center`}>
                                    <ShieldAlert className="h-3 w-3 mr-1" /> 
                                    {risk.owaspCategory?.id || 'N/A'}
                                  </Badge>
                                </TooltipTrigger>
                                <TooltipContent side="left" className="max-w-sm">
                                  <div className="max-w-xs">
                                    <p className="font-bold">{risk.owaspCategory.name}</p>
                                    <p className="text-xs">{risk.owaspCategory.description}</p>
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
                        {risk.owaspCategory && (
                          <div className="bg-gray-50 p-3 rounded-md border border-gray-200 text-sm space-y-1">
                            <div className="flex items-center gap-2">
                              <ShieldAlert className="h-4 w-4 text-gray-700" />
                              <h4 className="font-semibold">OWASP LLM Top 10 Classification:</h4>
                            </div>
                            <div className="pl-6">
                              <p className="font-medium">{risk.owaspCategory.id}: {risk.owaspCategory.name}</p>
                              <p className="text-gray-600 text-sm">{risk.owaspCategory.description}</p>
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
                              riskIndex={idx} 
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
          </div>
        ))}
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
