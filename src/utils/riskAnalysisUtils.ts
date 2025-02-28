
import { CodeReference, SecurityRisk, AIComponent } from "@/types/reportTypes";
import { extractPromptsFromCode, createSystemPromptRisk } from "./promptDetectionUtils";

// Get the code references for a specific security risk using the IDs
export const getRelatedCodeReferences = (
  risk: SecurityRisk,
  verifiedCodeReferences: CodeReference[]
) => {
  return verifiedCodeReferences.filter(
    (ref) => risk.related_code_references && risk.related_code_references.includes(ref.id)
  );
};

// Get AI components that might be related to a security risk
export const getRelatedAIComponents = (
  risk: SecurityRisk,
  aiComponents: AIComponent[]
) => {
  // Get the risk name from either risk or risk_name field
  const riskName = risk.risk || risk.risk_name;
  
  // Add null check for risk name
  if (!risk || !riskName) {
    console.error("Invalid risk object in getRelatedAIComponents:", risk);
    return [];
  }
  
  const riskLower = riskName.toLowerCase();

  // Map risks to relevant component types
  const riskToComponentTypes: Record<string, string[]> = {
    "prompt injection": ["LLM Provider", "LLM Framework", "Local LLM"],
    "data leakage": ["Vector Database", "RAG Framework", "Embedding Model", "LLM Provider", "LLM Framework"],
    "hallucination": ["LLM Provider", "LLM Framework", "Local LLM"],
    "api key exposure": ["LLM Provider", "Vector Database"],
    "model poisoning": ["LLM Provider", "LLM Framework", "ML Framework"],
    "hardcoded system prompts": ["LLM Provider", "LLM Framework", "Local LLM"],
  };

  // Find the matching risk pattern
  const matchingPattern = Object.keys(riskToComponentTypes).find((pattern) =>
    riskLower.includes(pattern)
  );

  if (matchingPattern) {
    const relevantTypes = riskToComponentTypes[matchingPattern];
    return aiComponents.filter((comp) => relevantTypes.includes(comp.type));
  }

  // Default - if no specific matching, return all components for risks with vector/RAG/LLM keywords
  if (
    riskLower.includes("vector") ||
    riskLower.includes("rag") ||
    riskLower.includes("llm") ||
    riskLower.includes("ai")
  ) {
    return aiComponents;
  }

  return [];
};

// Get code references that aren't related to any security risks
export const getUnrelatedCodeReferences = (
  securityRisks: SecurityRisk[],
  verifiedCodeReferences: CodeReference[]
) => {
  const allRiskRefIds = new Set(
    securityRisks.flatMap((risk) => risk.related_code_references || [])
  );

  return verifiedCodeReferences.filter((ref) => !allRiskRefIds.has(ref.id));
};

// Process code references to detect hardcoded system prompts
export const detectSystemPrompts = (codeReferences: CodeReference[]): {
  promptRisk: SecurityRisk | null;
  promptReferences: CodeReference[];
} => {
  const promptReferences: CodeReference[] = [];
  
  // Analyze each code reference for potential hardcoded prompts
  codeReferences.forEach(ref => {
    const extractedPrompts = extractPromptsFromCode(ref.snippet, ref.file);
    promptReferences.push(...extractedPrompts);
  });
  
  // Create a security risk if prompts were found
  const promptRisk = createSystemPromptRisk(promptReferences);
  
  return { promptRisk, promptReferences };
};

// Map risk types to OWASP LLM Top 10 categories (2025 version)
const owaspCategoryMap: Record<string, { id: string; name: string; description: string }> = {
  "prompt injection": {
    id: "LLM01:2025",
    name: "Prompt Injection",
    description: "A vulnerability where user inputs manipulate the LLM's behavior by altering its prompts."
  },
  "sensitive information disclosure": {
    id: "LLM02:2025", 
    name: "Sensitive Information Disclosure",
    description: "Risks involving the exposure of confidential data within the LLM or its applications."
  },
  "supply chain": {
    id: "LLM03:2025",
    name: "Supply Chain", 
    description: "Vulnerabilities arising from the components and dependencies used in LLM development and deployment."
  },
  "data and model poisoning": {
    id: "LLM04:2025",
    name: "Data and Model Poisoning",
    description: "Threats where malicious data is introduced during training, fine-tuning, or embedding processes."
  },
  "improper output handling": {
    id: "LLM05:2025", 
    name: "Improper Output Handling",
    description: "Issues stemming from inadequate validation, sanitization, or escaping of LLM outputs."
  },
  "excessive agency": {
    id: "LLM06:2025",
    name: "Excessive Agency",
    description: "Concerns related to LLM systems being granted more autonomy than intended, leading to unintended actions."
  },
  "system prompt leakage": {
    id: "LLM07:2025",
    name: "System Prompt Leakage",
    description: "The exposure of system-level prompts that can reveal internal configurations or logic."
  },
  "vector and embedding weaknesses": {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Security risks associated with the use of vectors and embeddings in LLM systems."
  },
  "misinformation": {
    id: "LLM09:2025",
    name: "Misinformation",
    description: "The potential for LLMs to generate and propagate false or misleading information."
  },
  "unbounded consumption": {
    id: "LLM10:2025",
    name: "Unbounded Consumption",
    description: "Scenarios where LLMs consume resources without limits, potentially leading to denial of service."
  },
  // Additional mappings for common risk types that might not directly match the category names
  "data leakage": {
    id: "LLM02:2025",
    name: "Sensitive Information Disclosure",
    description: "Risks involving the exposure of confidential data within the LLM or its applications."
  },
  "hallucination": {
    id: "LLM09:2025",
    name: "Misinformation",
    description: "The potential for LLMs to generate and propagate false or misleading information."
  },
  "api key exposure": {
    id: "LLM03:2025",
    name: "Supply Chain",
    description: "Vulnerabilities arising from the components and dependencies used in LLM development and deployment."
  },
  "model poisoning": {
    id: "LLM04:2025",
    name: "Data and Model Poisoning",
    description: "Threats where malicious data is introduced during training, fine-tuning, or embedding processes."
  },
  "denial of service": {
    id: "LLM10:2025",
    name: "Unbounded Consumption",
    description: "Scenarios where LLMs consume resources without limits, potentially leading to denial of service."
  },
  "embedding vulnerability": {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Security risks associated with the use of vectors and embeddings in LLM systems."
  },
  "rag poisoning": {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Security risks associated with the use of vectors and embeddings in LLM systems."
  },
  "vector store": {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Security risks associated with the use of vectors and embeddings in LLM systems."
  },
  "hardcoded system prompts": {
    id: "LLM07:2025",
    name: "System Prompt Leakage",
    description: "The exposure of system-level prompts that can reveal internal configurations or logic."
  }
};

// Enhance report by connecting code references to relevant security risks and adding OWASP categories
export const enhanceCodeReferences = (
  securityRisks: SecurityRisk[],
  verifiedCodeReferences: CodeReference[],
  confidenceScore: number
) => {
  // Create a map of risk types for easy lookup
  const riskTypes = {
    promptInjection: "prompt injection",
    dataLeakage: "data leakage",
    hallucination: "hallucination",
    apiKeyExposure: "api key exposure",
    modelPoisoning: "model poisoning",
    systemPromptLeakage: "hardcoded system prompts",
  };

  // Process code references to detect hardcoded system prompts
  const { promptRisk, promptReferences } = detectSystemPrompts(verifiedCodeReferences);
  
  // Add system prompt risk if detected
  if (promptRisk) {
    const existingPromptRisk = securityRisks.find(risk => {
      const riskName = risk.risk || risk.risk_name;
      return riskName && riskName.toLowerCase().includes(riskTypes.systemPromptLeakage);
    });
    
    if (existingPromptRisk) {
      // Update existing risk with new references
      existingPromptRisk.related_code_references = [
        ...new Set([
          ...(existingPromptRisk.related_code_references || []),
          ...promptRisk.related_code_references
        ])
      ];
    } else {
      // Add new risk
      securityRisks.push(promptRisk);
    }
    
    // Add prompt references to verified code references if they don't already exist
    const existingIds = new Set(verifiedCodeReferences.map(ref => ref.id));
    promptReferences.forEach(ref => {
      if (!existingIds.has(ref.id)) {
        verifiedCodeReferences.push(ref);
      }
    });
  }

  // Add OWASP categories to security risks if they don't have them
  securityRisks.forEach(risk => {
    if (!risk) {
      console.error("Invalid risk object:", risk);
      return; // Skip this risk and continue with the next one
    }
    
    // Get risk name from either field
    const riskName = risk.risk || risk.risk_name;
    if (!riskName) {
      console.error("Risk object missing both risk and risk_name:", risk);
      return;
    }
    
    const riskLower = riskName.toLowerCase();
    
    // Find the matching OWASP category
    if (!risk.owasp_category) {
      for (const [riskType, owaspInfo] of Object.entries(owaspCategoryMap)) {
        if (riskLower.includes(riskType)) {
          risk.owasp_category = owaspInfo;
          break;
        }
      }
      
      // Default to LLM05:2025 Improper Output Handling if no specific match
      if (!risk.owasp_category) {
        risk.owasp_category = {
          id: "LLM05:2025",
          name: "Improper Output Handling",
          description: "Issues stemming from inadequate validation, sanitization, or escaping of LLM outputs."
        };
      }
    }
  });

  // Find all security risks
  const promptInjectionRisk = securityRisks.find((risk) => {
    const riskName = risk.risk || risk.risk_name;
    return riskName && riskName.toLowerCase().includes(riskTypes.promptInjection);
  });

  const dataLeakageRisk = securityRisks.find((risk) => {
    const riskName = risk.risk || risk.risk_name;
    return riskName && riskName.toLowerCase().includes(riskTypes.dataLeakage);
  });

  const hallucinationRisk = securityRisks.find((risk) => {
    const riskName = risk.risk || risk.risk_name;
    return riskName && riskName.toLowerCase().includes(riskTypes.hallucination);
  });

  const apiKeyExposureRisk = securityRisks.find((risk) => {
    const riskName = risk.risk || risk.risk_name;
    return riskName && riskName.toLowerCase().includes(riskTypes.apiKeyExposure);
  });

  // Initialize related_code_references arrays if they don't exist
  securityRisks.forEach((risk) => {
    if (risk && !risk.related_code_references) {
      risk.related_code_references = [];
    }
  });

  // Associate code references with appropriate risks
  verifiedCodeReferences.forEach((ref) => {
    if (!ref || !ref.file || !ref.snippet) {
      console.error("Invalid code reference:", ref);
      return; // Skip this reference and continue with the next one
    }
    
    const fileName = ref.file.toLowerCase();
    const snippet = ref.snippet.toLowerCase();

    // Common file extensions to watch for
    const isCodeFile =
      fileName.endsWith(".py") ||
      fileName.endsWith(".js") ||
      fileName.endsWith(".ts") ||
      fileName.endsWith(".tsx") ||
      fileName.endsWith(".jsx") ||
      fileName.endsWith(".java") ||
      fileName.endsWith(".go");

    // LLM-related patterns for prompt injection - ONLY industry standard terms
    const llmKeywords = [
      "llm", "chat", "ai", "bot", "gpt", "openai", "prompt", "claude", "anthropic",
      "mistral", "gemini", "langchain", "completion", "model", "assistant", "language model",
      "token", "generate", "huggingface", "inference", "agent", "transformer", "bert", "dalle",
      "diffusion", "stable diffusion", "whisper", "phi", "llama", "davinci", "turbo"
    ];

    // Check if any LLM keyword is in the file name or snippet
    const isLlmRelated =
      llmKeywords.some((keyword) => fileName.includes(keyword)) ||
      llmKeywords.some((keyword) => snippet.includes(keyword));

    // RAG/Vector DB patterns for data leakage - ONLY industry standard terms
    const ragKeywords = [
      "rag", "vector", "embed", "chromadb", "pinecone", "weaviate", "qdrant", "faiss",
      "index", "search", "retrieval", "retriever", "retrieve", "document", "knowledge",
      "database", "store", "langchain", "llamaindex", "semantic"
    ];

    // Check if any RAG keyword is in the file name or snippet
    const isRagRelated =
      ragKeywords.some((keyword) => fileName.includes(keyword)) ||
      ragKeywords.some((keyword) => snippet.includes(keyword));

    // API key patterns - generic credential patterns
    const apiKeyKeywords = [
      "api_key", "apikey", "api-key", "secret", "token", "password", "credential",
      "auth", "key", "api_token", "access_token", "oauth", "bearer", ".env"
    ];

    // Check if any API key keyword is in the snippet
    const isApiKeyRelated = apiKeyKeywords.some((keyword) => snippet.includes(keyword));

    // Generic AI code patterns - common in AI implementations but not specific to any framework
    const aiPatterns = [
      "api", "http", "fetch", "axios", "response", "request",
      "temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty",
      "system message", "user message", "conversation", "context"
    ];

    // Is this likely AI-related code based on generic patterns?
    const isLikelyAICode =
      isCodeFile &&
      (isLlmRelated ||
        isRagRelated ||
        (confidenceScore > 0.7 && // High confidence this is an AI repo
          aiPatterns.some((pattern) => snippet.includes(pattern))));

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

  return securityRisks;
};
