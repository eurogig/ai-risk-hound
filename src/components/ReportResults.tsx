
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { InfoIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
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

  // Enhance report by connecting code references to relevant security risks
  const enhanceCodeReferences = () => {
    // Create a map of risk types for easy lookup
    const riskTypes = {
      promptInjection: 'prompt injection',
      dataLeakage: 'data leakage',
      hallucination: 'hallucination',
      apiKeyExposure: 'api key exposure',
      modelPoisoning: 'model poisoning',
    };
    
    // Find all security risks
    const promptInjectionRisk = report.security_risks.find(risk => 
      risk.risk.toLowerCase().includes(riskTypes.promptInjection)
    );
    
    const dataLeakageRisk = report.security_risks.find(risk => 
      risk.risk.toLowerCase().includes(riskTypes.dataLeakage)
    );
    
    const hallucinationRisk = report.security_risks.find(risk => 
      risk.risk.toLowerCase().includes(riskTypes.hallucination)
    );
    
    const apiKeyExposureRisk = report.security_risks.find(risk => 
      risk.risk.toLowerCase().includes(riskTypes.apiKeyExposure)
    );
    
    // Initialize related_code_references arrays if they don't exist
    report.security_risks.forEach(risk => {
      if (!risk.related_code_references) {
        risk.related_code_references = [];
      }
    });
    
    // Associate code references with appropriate risks
    verifiedCodeReferences.forEach(ref => {
      const fileName = ref.file.toLowerCase();
      const snippet = ref.snippet.toLowerCase();
      
      // Common file extensions to watch for
      const isCodeFile = 
        fileName.endsWith('.py') || 
        fileName.endsWith('.js') || 
        fileName.endsWith('.ts') || 
        fileName.endsWith('.tsx') || 
        fileName.endsWith('.jsx') || 
        fileName.endsWith('.java') || 
        fileName.endsWith('.go');
      
      // LLM-related patterns for prompt injection - ONLY industry standard terms
      const llmKeywords = [
        'llm', 'chat', 'ai', 'bot', 'gpt', 'openai', 'prompt', 'claude', 'anthropic', 
        'mistral', 'gemini', 'langchain', 'completion', 'model', 'assistant', 'language model',
        'token', 'generate', 'huggingface', 'inference', 'agent', 'transformer', 'bert', 'dalle', 
        'diffusion', 'stable diffusion', 'whisper', 'phi', 'llama', 'davinci', 'turbo'
      ];
      
      // Check if any LLM keyword is in the file name or snippet
      const isLlmRelated = 
        llmKeywords.some(keyword => fileName.includes(keyword)) || 
        llmKeywords.some(keyword => snippet.includes(keyword));
      
      // RAG/Vector DB patterns for data leakage - ONLY industry standard terms
      const ragKeywords = [
        'rag', 'vector', 'embed', 'chromadb', 'pinecone', 'weaviate', 'qdrant', 'faiss',
        'index', 'search', 'retrieval', 'retriever', 'retrieve', 'document', 'knowledge', 
        'database', 'store', 'langchain', 'llamaindex', 'semantic'
      ];
      
      // Check if any RAG keyword is in the file name or snippet
      const isRagRelated = 
        ragKeywords.some(keyword => fileName.includes(keyword)) || 
        ragKeywords.some(keyword => snippet.includes(keyword));
      
      // API key patterns - generic credential patterns
      const apiKeyKeywords = [
        'api_key', 'apikey', 'api-key', 'secret', 'token', 'password', 'credential', 
        'auth', 'key', 'api_token', 'access_token', 'oauth', 'bearer', '.env'
      ];
      
      // Check if any API key keyword is in the snippet
      const isApiKeyRelated = apiKeyKeywords.some(keyword => snippet.includes(keyword));
      
      // Generic AI code patterns - common in AI implementations but not specific to any framework
      const aiPatterns = [
        'api', 'http', 'fetch', 'axios', 'response', 'request',
        'temperature', 'max_tokens', 'top_p', 'frequency_penalty', 'presence_penalty',
        'system message', 'user message', 'conversation', 'context'
      ];
      
      // Is this likely AI-related code based on generic patterns?
      const isLikelyAICode = isCodeFile && 
        (isLlmRelated || isRagRelated || 
         (report.confidence_score > 0.7 && // High confidence this is an AI repo
          aiPatterns.some(pattern => snippet.includes(pattern))));
      
      // Associate with prompt injection risk if LLM related
      if (promptInjectionRisk && (isLlmRelated || isLikelyAICode)) {
        if (!promptInjectionRisk.related_code_references.includes(ref.id)) {
          promptInjectionRisk.related_code_references.push(ref.id);
        }
      }
      
      // Associate with data leakage risk if RAG related
      if (dataLeakageRisk && (isRagRelated || isLlmRelated)) {
        if (!dataLeakageRisk.related_code_references.includes(ref.id)) {
          dataLeakageRisk.related_code_references.push(ref.id);
        }
      }
      
      // Associate with API key exposure risk if API key related
      if (apiKeyExposureRisk && isApiKeyRelated) {
        if (!apiKeyExposureRisk.related_code_references.includes(ref.id)) {
          apiKeyExposureRisk.related_code_references.push(ref.id);
        }
      }
      
      // Associate with hallucination risk if LLM related (LLMs can hallucinate)
      if (hallucinationRisk && (isLlmRelated || isLikelyAICode)) {
        if (!hallucinationRisk.related_code_references.includes(ref.id)) {
          hallucinationRisk.related_code_references.push(ref.id);
        }
      }
    });
    
    return report;
  };
  
  // Enhance the report by filling in missing connections
  const enhancedReport = enhanceCodeReferences();

  // Get the code references for a specific security risk using the IDs
  const getRelatedCodeReferences = (risk: { risk: string; related_code_references: string[] }) => {
    return verifiedCodeReferences.filter(ref => 
      risk.related_code_references && risk.related_code_references.includes(ref.id)
    );
  };

  // Get AI components that might be related to a security risk
  const getRelatedAIComponents = (risk: { risk: string }) => {
    const riskLower = risk.risk.toLowerCase();
    
    // Map risks to relevant component types
    const riskToComponentTypes: Record<string, string[]> = {
      "prompt injection": ["LLM Provider", "LLM Framework", "Local LLM"],
      "data leakage": ["Vector Database", "RAG Framework", "Embedding Model", "LLM Provider", "LLM Framework"],
      "hallucination": ["LLM Provider", "LLM Framework", "Local LLM"],
      "api key exposure": ["LLM Provider", "Vector Database"],
      "model poisoning": ["LLM Provider", "LLM Framework", "ML Framework"],
    };
    
    // Find the matching risk pattern
    const matchingPattern = Object.keys(riskToComponentTypes).find(pattern => 
      riskLower.includes(pattern)
    );
    
    if (matchingPattern) {
      const relevantTypes = riskToComponentTypes[matchingPattern];
      return report.ai_components_detected.filter(comp => 
        relevantTypes.includes(comp.type)
      );
    }
    
    // Default - if no specific matching, return all components for risks with vector/RAG/LLM keywords
    if (riskLower.includes("vector") || riskLower.includes("rag") || riskLower.includes("llm") || riskLower.includes("ai")) {
      return report.ai_components_detected;
    }
    
    return [];
  };

  // Get code references that aren't related to any security risks
  const getUnrelatedCodeReferences = () => {
    const allRiskRefIds = new Set(
      enhancedReport.security_risks.flatMap(risk => risk.related_code_references || [])
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

      {/* Security Risks Section - Now placed IMMEDIATELY after confidence score */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Security Risks</CardTitle>
        </CardHeader>
        <CardContent>
          {enhancedReport.security_risks.length > 0 ? (
            <Accordion type="single" collapsible className="w-full">
              {enhancedReport.security_risks.map((risk, index) => {
                // Get code references related to this specific risk using the IDs
                const relatedReferences = getRelatedCodeReferences(risk);
                // Get AI components potentially related to this risk
                const relatedComponents = getRelatedAIComponents(risk);
                
                return (
                  <AccordionItem key={index} value={`risk-${index}`}>
                    <AccordionTrigger className="hover:no-underline py-3">
                      <div className="flex items-center justify-between w-full pr-4">
                        <span className="font-medium text-left">{risk.risk}</span>
                        <Badge className={`${getSeverityColor(risk.severity)} ml-2`}>
                          {risk.severity}
                        </Badge>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="space-y-4 pt-2">
                        <p className="text-gray-600">{risk.description}</p>
                        
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
                        
                        {/* Code Evidence for this risk - always display the section header */}
                        <div className="mt-4">
                          <h4 className="text-sm font-medium text-gray-700 mb-2">Evidence in Code:</h4>
                          {relatedReferences.length > 0 ? (
                            <Accordion type="single" collapsible className="w-full">
                              {relatedReferences.map((reference, refIndex) => (
                                <AccordionItem key={refIndex} value={`risk-${index}-ref-${refIndex}`} className="border border-gray-100 rounded-md mb-2">
                                  <AccordionTrigger className="hover:no-underline text-sm px-3 py-2">
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

      {/* AI Components Section - Moved below security risks */}
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

      {/* Additional Code References Section (showing references not connected to security risks) */}
      {getUnrelatedCodeReferences().length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xl">Additional AI References in Code</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-gray-500 mb-3">
              These code references show AI implementations not directly associated with any detected security risks.
            </p>
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
          <div className="space-y-6">
            <ul className="space-y-2 list-disc pl-5">
              {report.remediation_suggestions.map((suggestion, index) => (
                <li key={index} className="text-gray-700">{suggestion}</li>
              ))}
            </ul>
            
            {/* Call to Action Button */}
            <div className="pt-4 flex justify-center">
              <a href="https://www.straiker.ai/" target="_blank" rel="noopener noreferrer">
                <Button className="bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 shadow-lg">
                  Is Your AI Secure? Find Out with a Free AI Risk Assessment
                </Button>
              </a>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ReportResults;
