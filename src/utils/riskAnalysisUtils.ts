
import { CodeReference, SecurityRisk, AIComponent } from "@/types/reportTypes";
import { extractPromptsFromCode, createSystemPromptRisk } from "./promptDetectionUtils";

export const getRelatedCodeReferences = (
  risk: SecurityRisk,
  verifiedCodeReferences: CodeReference[]
) => {
  // If risk has no related_code_references, check for system prompt related references by type
  if (!risk.related_code_references || risk.related_code_references.length === 0) {
    // Check if this is a system prompt risk
    const riskName = risk.risk || risk.risk_name || '';
    const isSystemPromptRisk = riskName.toLowerCase().includes('system prompt') || 
                               riskName.toLowerCase().includes('hardcoded');
                               
    if (isSystemPromptRisk) {
      // Find prompt related references
      return verifiedCodeReferences.filter(ref => 
        ref.type === 'prompt_definition' || 
        ref.snippet.toLowerCase().includes('system_prompt') ||
        ref.snippet.toLowerCase().includes('system prompt')
      );
    }
  }

  // Return references based on ID relationship
  return verifiedCodeReferences.filter(
    (ref) => risk.related_code_references && risk.related_code_references.includes(ref.id)
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
  
  // Check specifically for system prompt references
  const promptDefinitionRefs = verifiedCodeReferences.filter(ref => 
    ref.type === 'prompt_definition' || 
    ref.snippet.toLowerCase().includes('system_prompt') ||
    ref.snippet.toLowerCase().includes('system prompt')
  );
  
  console.log("Found prompt definition references:", promptDefinitionRefs.length);
  
  // Check if we already have a system prompt risk
  const hasSystemPromptRisk = enhancedRisks.some(risk => {
    const riskName = (risk.risk || risk.risk_name || "").toLowerCase();
    return riskName.includes('system prompt') || riskName.includes('hardcoded system');
  });
  
  // If we have prompt references but no system prompt risk, create one
  if (promptDefinitionRefs.length > 0 && !hasSystemPromptRisk) {
    console.log("Adding missing system prompt risk");
    const systemPromptRisk = createSystemPromptRisk(
      promptDefinitionRefs.map(ref => ref.id),
      confidenceScore
    );
    enhancedRisks.push(systemPromptRisk);
  }
  
  return enhancedRisks;
};

export const getUnrelatedCodeReferences = (
  securityRisks: SecurityRisk[],
  verifiedCodeReferences: CodeReference[]
): CodeReference[] => {
  // Get all the code reference IDs that are related to security risks
  const relatedReferenceIds = new Set<string>();
  
  securityRisks.forEach(risk => {
    if (risk.related_code_references) {
      risk.related_code_references.forEach(refId => {
        relatedReferenceIds.add(refId);
      });
    }
  });
  
  // Also check for prompt definitions that should be related to system prompt risks
  const promptDefReferences = verifiedCodeReferences.filter(ref => 
    ref.type === 'prompt_definition' || 
    ref.snippet.toLowerCase().includes('system_prompt') ||
    ref.snippet.toLowerCase().includes('system prompt')
  );
  
  promptDefReferences.forEach(ref => {
    relatedReferenceIds.add(ref.id);
  });
  
  // Return only the code references that aren't related to any security risks
  return verifiedCodeReferences.filter(
    ref => !relatedReferenceIds.has(ref.id)
  );
};
