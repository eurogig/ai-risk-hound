
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert } from "lucide-react";
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
  securityRisks: SecurityRisk[];
  verifiedCodeReferences: CodeReference[];
  aiComponents: AIComponent[];
}

const SecurityRisksCard = ({ 
  securityRisks, 
  verifiedCodeReferences,
  aiComponents
}: SecurityRisksCardProps) => {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">Security Risks</CardTitle>
      </CardHeader>
      <CardContent>
        {securityRisks.length > 0 ? (
          <Accordion type="single" collapsible className="w-full">
            {securityRisks.map((risk, index) => {
              // Get code references related to this specific risk using the IDs
              const relatedReferences = getRelatedCodeReferences(risk, verifiedCodeReferences);
              // Get AI components potentially related to this risk
              const relatedComponents = getRelatedAIComponents(risk, aiComponents);
              
              return (
                <AccordionItem key={index} value={`risk-${index}`}>
                  <AccordionTrigger className="hover:no-underline py-3">
                    <div className="flex items-center justify-between w-full pr-4">
                      <span className="font-medium text-left">{risk.risk}</span>
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
                              <TooltipContent>
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
                          <p className="text-sm text-gray-500 italic">No specific code references found for this risk.</p>
                        )}
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
      </CardContent>
    </Card>
  );
};

export default SecurityRisksCard;
