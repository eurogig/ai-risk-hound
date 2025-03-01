
import { SecurityRisk } from "@/types/reportTypes";

export const extractPromptsFromCode = (code: string): string[] => {
  // Look for strings that might be system prompts
  const promptPatterns = [
    /SYSTEM_PROMPT\s*=\s*["'`](.*?)["'`]/gs,
    /systemPrompt\s*=\s*["'`](.*?)["'`]/gs,
    /system_prompt\s*=\s*["'`](.*?)["'`]/gs,
    /content:\s*["'`](You are.*?)["'`]/gs,
    /"role":\s*["']system["'],\s*"content":\s*["'`](.*?)["'`]/gs,
    /role:\s*["']system["'],\s*content:\s*["'`](.*?)["'`]/gs,
    /messages:\s*\[\s*{\s*role:\s*["']system["'],\s*content:\s*["'`](.*?)["'`]/gs,
  ];
  
  const extractedPrompts: string[] = [];
  
  for (const pattern of promptPatterns) {
    let match;
    while ((match = pattern.exec(code)) !== null) {
      if (match[1] && match[1].length > 10) {  // Ensure it's not just a tiny string
        extractedPrompts.push(match[1]);
      }
    }
  }
  
  return extractedPrompts;
};

export const createSystemPromptRisk = (
  relatedCodeReferenceIds: string[],
  confidenceScore: number
): SecurityRisk => {
  // Create a system prompt risk with appropriate OWASP categorization
  return {
    risk: "Hardcoded System Prompts",
    risk_name: "Hardcoded System Prompts",
    severity: "Medium",
    description: "System prompts are hardcoded in the codebase, which may lead to prompt disclosure, system prompt injection, or unauthorized modifications to AI behavior.",
    related_code_references: relatedCodeReferenceIds,
    owasp_category: {
      id: "LLM01:2025",
      name: "Prompt Injection",
      description: "Hardcoded system prompts can reveal AI system instructions and potentially enable attackers to craft prompt injections that bypass security controls."
    }
  };
};
