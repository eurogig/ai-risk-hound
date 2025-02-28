
import { CodeReference, SecurityRisk, AIComponent } from "@/types/reportTypes";

// Get the code references for a specific security risk using the IDs
export const getRelatedCodeReferences = (
  risk: { risk: string; related_code_references: string[] },
  verifiedCodeReferences: CodeReference[]
) => {
  return verifiedCodeReferences.filter(
    (ref) => risk.related_code_references && risk.related_code_references.includes(ref.id)
  );
};

// Get AI components that might be related to a security risk
export const getRelatedAIComponents = (
  risk: { risk: string },
  aiComponents: AIComponent[]
) => {
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

// Map risk types to OWASP LLM Top 10 categories
const owaspCategoryMap: Record<string, { id: string; name: string; description: string }> = {
  "prompt injection": {
    id: "LLM01",
    name: "Prompt Injection",
    description: "Manipulating LLM behavior by crafting inputs that exploit its core functionality to produce harmful, unauthorized, or unintended outputs."
  },
  "data leakage": {
    id: "LLM07",
    name: "Data Leakage",
    description: "LLMs may inadvertently memorize and reveal sensitive information from their training data or collected through interactions."
  },
  "hallucination": {
    id: "LLM08",
    name: "Excessive Agency",
    description: "When LLMs act beyond their authorized scope or make decisions without sufficient oversight, leading to unintended consequences."
  },
  "api key exposure": {
    id: "LLM05",
    name: "Supply Chain Vulnerabilities",
    description: "Weaknesses in the ecosystem of tools, libraries, and integrations that support LLM applications, creating attack vectors."
  },
  "model poisoning": {
    id: "LLM06",
    name: "Insecure Plugins",
    description: "Exploitable weaknesses in plugins and extensions that expand LLM functionality, potentially bypassing security boundaries."
  },
  "insufficient access control": {
    id: "LLM03",
    name: "Training Data Poisoning",
    description: "Manipulating an LLM's training data to induce harmful behaviors or create backdoors that can be exploited later."
  },
  "sensitive data exposure": {
    id: "LLM04",
    name: "Sensitive Information Disclosure",
    description: "LLMs may reveal sensitive information from previous interactions or their training data if prompted correctly."
  },
  "insecure output handling": {
    id: "LLM09",
    name: "Overreliance",
    description: "Excessive trust in LLM outputs without verification, potentially leading to propagation of incorrect or harmful information."
  },
  "denial of service": {
    id: "LLM10",
    name: "Denial of Service",
    description: "Exploiting LLM resource consumption to degrade application performance or cause excessive costs through specially crafted inputs."
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
  };

  // Add OWASP categories to security risks if they don't have them
  securityRisks.forEach(risk => {
    const riskLower = risk.risk.toLowerCase();
    
    // Find the matching OWASP category
    if (!risk.owasp_category) {
      for (const [riskType, owaspInfo] of Object.entries(owaspCategoryMap)) {
        if (riskLower.includes(riskType)) {
          risk.owasp_category = owaspInfo;
          break;
        }
      }
      
      // Default to LLM02 Security Control Failure if no specific match
      if (!risk.owasp_category) {
        risk.owasp_category = {
          id: "LLM02",
          name: "Security Control Failure",
          description: "Failures in implementing adequate security controls in LLM applications, leading to vulnerabilities."
        };
      }
    }
  });

  // Find all security risks
  const promptInjectionRisk = securityRisks.find((risk) =>
    risk.risk.toLowerCase().includes(riskTypes.promptInjection)
  );

  const dataLeakageRisk = securityRisks.find((risk) =>
    risk.risk.toLowerCase().includes(riskTypes.dataLeakage)
  );

  const hallucinationRisk = securityRisks.find((risk) =>
    risk.risk.toLowerCase().includes(riskTypes.hallucination)
  );

  const apiKeyExposureRisk = securityRisks.find((risk) =>
    risk.risk.toLowerCase().includes(riskTypes.apiKeyExposure)
  );

  // Initialize related_code_references arrays if they don't exist
  securityRisks.forEach((risk) => {
    if (!risk.related_code_references) {
      risk.related_code_references = [];
    }
  });

  // Associate code references with appropriate risks
  verifiedCodeReferences.forEach((ref) => {
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
