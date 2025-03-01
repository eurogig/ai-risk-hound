import { CodeReference, SecurityRisk, AIComponent } from "@/types/reportTypes";
import { extractPromptsFromCode, createSystemPromptRisk } from "./promptDetectionUtils";

export const getRelatedCodeReferences = (
  risk: SecurityRisk,
  verifiedCodeReferences: CodeReference[]
) => {
  // Simply return references based on pre-computed relationships
  return verifiedCodeReferences.filter(
    (ref) => risk.related_code_references?.includes(ref.id)
  );
};

export const getRelatedAIComponents = (
  risk: SecurityRisk,
  aiComponents: AIComponent[]
) => {
  // Determine which AI components are related to this risk
  const riskName = (risk.risk || risk.risk_name || "").toLowerCase();
  
  // For now we'll consider all components potentially related to all risks
  // This could be made more specific in the future
  return aiComponents;
};

export const enhanceCodeReferences = (
  securityRisks: SecurityRisk[],
  verifiedCodeReferences: CodeReference[],
  confidenceScore: number
): SecurityRisk[] => {
  // Make a deep copy to avoid mutating the original array
  const enhancedRisks = JSON.parse(JSON.stringify(securityRisks)) as SecurityRisk[];
  
  // Process all risks, ensuring each is handled properly
  for (const risk of enhancedRisks) {
    // If this is a system prompt risk with empty related_code_references
    if ((risk.risk || "").toLowerCase().includes('hardcoded system prompt') || 
        (risk.risk || "").toLowerCase().includes('system prompt leak')) {
      
      // Find prompt definition references
      const promptDefinitionRefs = verifiedCodeReferences.filter(ref => 
        ref.type === 'prompt_definition' || 
        ref.snippet.toLowerCase().includes('system_prompt') ||
        ref.snippet.toLowerCase().includes('system prompt')
      );
      
      // Add these references to the risk if they exist
      if (promptDefinitionRefs.length > 0 && (!risk.related_code_references || risk.related_code_references.length === 0)) {
        risk.related_code_references = promptDefinitionRefs.map(ref => ref.id);
        console.log("Enhanced system prompt risk with references:", promptDefinitionRefs.length);
      }
    }
  }
  
  return enhancedRisks;
};

export const getUnrelatedCodeReferences = (
  securityRisks: SecurityRisk[],
  verifiedCodeReferences: CodeReference[]
): CodeReference[] => {
  // Use pre-computed relationships
  const relatedReferenceIds = new Set(
    securityRisks.flatMap(risk => risk.related_code_references || [])
  );
  return verifiedCodeReferences.filter(ref => !relatedReferenceIds.has(ref.id));
};
