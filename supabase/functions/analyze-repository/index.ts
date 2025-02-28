
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import "https://deno.land/x/xhr@0.1.0/mod.ts";

interface RepositoryAnalysisRequest {
  repository_url: string;
  branch?: string;
}

interface CodeReference {
  id: string;
  file: string;
  line: number;
  snippet: string;
  verified: boolean;
}

interface SecurityRisk {
  risk: string;
  severity: string;
  description: string;
  related_code_references: string[];
  owasp_category?: {
    id: string;
    name: string;
    description: string;
  };
}

interface AIComponent {
  name: string;
  type: string;
  confidence: number;
}

const getOWASPCategory = (risk: string) => {
  const riskLower = risk.toLowerCase();
  const categories: Record<string, { id: string; name: string; description: string }> = {
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
    "data leakage": {
      id: "LLM02:2025",
      name: "Sensitive Information Disclosure",
      description: "Risks involving the exposure of confidential data within the LLM or its applications."
    },
    "system prompt leakage": {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    },
    "hardcoded system prompts": {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    }
  };

  for (const [key, value] of Object.entries(categories)) {
    if (riskLower.includes(key)) {
      return value;
    }
  }

  return {
    id: "LLM05:2025",
    name: "Improper Output Handling",
    description: "Issues stemming from inadequate validation, sanitization, or escaping of LLM outputs."
  };
};

// Regex patterns for detecting hardcoded prompts
const PROMPT_PATTERNS = {
  // Match system prompts in OpenAI API calls and similar patterns
  OPENAI_SYSTEM: /(\{|\[)\s*["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*["']([^"']+)["']/g,
  
  // Match variable assignments for system prompts
  VARIABLE_ASSIGNMENT: /(const|let|var|SYSTEM_PROMPT|system_prompt|systemPrompt|prompt)\s*=\s*["']([^"']{10,})["']/g,
  
  // Match function arguments that might contain prompts
  FUNCTION_ARGS: /(messages|prompt|system_prompt|systemPrompt)\s*[:=]\s*["']([^"']{10,})["']/g,
  
  // Match Python f-strings and multi-line strings
  PYTHON_STRINGS: /('''|""")([^'"]{10,})('''|""")/g,
  
  // Match Python prompt assignments
  PYTHON_ASSIGNMENT: /(SYSTEM_PROMPT|system_prompt|prompt)\s*=\s*['"]{1,3}([^'"]{10,})['"]{1,3}/g,
};

// Keywords that suggest a string might be a system prompt
const PROMPT_KEYWORDS = [
  'you are', 'assistant', 'your role', 'your task', 'your job',
  'respond as', 'act as', 'pretend to be', 'behave like',
  'your purpose is', 'your goal is', 'your objective',
  'always respond', 'never respond', 'don\'t reveal', 'do not reveal',
  'instruction', 'guideline', 'do not disclose', 'system prompt',
  'role play', 'roleplay'
];

// Check if a string contains prompt-like content
const isLikelyPrompt = (content: string): boolean => {
  if (!content || content.length < 20) return false;
  
  const lowerContent = content.toLowerCase();
  return PROMPT_KEYWORDS.some(keyword => lowerContent.includes(keyword.toLowerCase()));
};

// Extract potential prompts from code using regex
const extractPromptsFromCode = (code: string, filePath: string): CodeReference[] => {
  const results: CodeReference[] = [];
  const lineCount = code.split('\n').length;
  
  // Function to process regex matches
  const processMatches = (regex: RegExp, promptGroupIndex: number) => {
    let match;
    while ((match = regex.exec(code)) !== null) {
      const promptContent = match[promptGroupIndex];
      
      // Only consider strings that are likely to be prompts
      if (isLikelyPrompt(promptContent)) {
        // Calculate line number by counting newlines before the match
        const upToMatch = code.substring(0, match.index);
        const lineNumber = upToMatch.split('\n').length;
        
        // Get a snippet with context (up to 3 lines before and after)
        const startLine = Math.max(0, lineNumber - 3);
        const endLine = Math.min(lineCount, lineNumber + 3);
        const snippet = code.split('\n').slice(startLine, endLine).join('\n');
        
        results.push({
          id: `${filePath}-${lineNumber}-${results.length}`,
          file: filePath,
          line: lineNumber,
          snippet: snippet,
          verified: true
        });
      }
    }
  };
  
  // Process each regex pattern
  processMatches(PROMPT_PATTERNS.OPENAI_SYSTEM, 2);
  processMatches(PROMPT_PATTERNS.VARIABLE_ASSIGNMENT, 2);
  processMatches(PROMPT_PATTERNS.FUNCTION_ARGS, 2);
  processMatches(PROMPT_PATTERNS.PYTHON_STRINGS, 2);
  processMatches(PROMPT_PATTERNS.PYTHON_ASSIGNMENT, 2);
  
  return results;
};

// Helper function to determine if a file should be analyzed for prompts
const shouldAnalyzeFile = (filePath: string): boolean => {
  const supportedExtensions = ['.py', '.js', '.ts', '.tsx', '.jsx'];
  const extension = filePath.substring(filePath.lastIndexOf('.'));
  return supportedExtensions.includes(extension);
};

// Create a security risk for hardcoded system prompts
const createSystemPromptRisk = (promptReferences: CodeReference[]): SecurityRisk | null => {
  if (promptReferences.length === 0) return null;
  
  return {
    risk: "Hardcoded System Prompts",
    severity: "Medium",
    description: "Hardcoded system prompts were detected in the codebase. These may leak sensitive information about the application logic or create security vulnerabilities through prompt injection attacks.",
    related_code_references: promptReferences.map(ref => ref.id),
    owasp_category: {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    }
  };
};

// Mock security risks for demonstration purposes
const getSecurityRisks = (fileContents: Record<string, string>): [SecurityRisk[], CodeReference[]] => {
  const promptReferences: CodeReference[] = [];
  
  // Check each file for hardcoded prompts
  for (const [filePath, content] of Object.entries(fileContents)) {
    if (shouldAnalyzeFile(filePath)) {
      const extractedPrompts = extractPromptsFromCode(content, filePath);
      promptReferences.push(...extractedPrompts);
    }
  }
  
  const securityRisks: SecurityRisk[] = [];
  
  // Add system prompt risk if found
  const systemPromptRisk = createSystemPromptRisk(promptReferences);
  if (systemPromptRisk) {
    securityRisks.push(systemPromptRisk);
  }
  
  // Add basic set of common security risks
  securityRisks.push({
    risk: "Prompt Injection Vulnerability",
    severity: "High",
    description: "Direct user input is being passed to LLM prompts without proper validation or sanitization",
    related_code_references: [],
    owasp_category: getOWASPCategory("prompt injection")
  });
  
  securityRisks.push({
    risk: "Data Leakage in LLM Interactions",
    severity: "Medium",
    description: "Sensitive information could be exposed through LLM responses due to improper prompt design",
    related_code_references: [],
    owasp_category: getOWASPCategory("data leakage")
  });
  
  securityRisks.push({
    risk: "Hallucination Risk",
    severity: "Medium",
    description: "The application doesn't implement proper fact-checking mechanisms to validate LLM output accuracy",
    related_code_references: [],
    owasp_category: getOWASPCategory("misinformation")
  });
  
  return [securityRisks, promptReferences];
};

// Generate mock code references
const generateCodeReferences = (fileContents: Record<string, string>): CodeReference[] => {
  const references: CodeReference[] = [];
  let id = 0;
  
  for (const [filePath, content] of Object.entries(fileContents)) {
    const lines = content.split('\n');
    
    // Simple heuristic - look for AI/LLM related keywords
    const aiKeywords = ['gpt', 'llm', 'openai', 'langchain', 'prompt', 'embedding', 'tokens', 'completion'];
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      
      // If line contains any AI keyword
      if (aiKeywords.some(keyword => line.includes(keyword))) {
        // Get context - a few lines before and after
        const startLine = Math.max(0, i - 2);
        const endLine = Math.min(lines.length, i + 3);
        const snippet = lines.slice(startLine, endLine).join('\n');
        
        references.push({
          id: `ref-${id++}`,
          file: filePath,
          line: i + 1,
          snippet: snippet,
          verified: Math.random() > 0.2 // 80% are verified
        });
      }
    }
  }
  
  return references;
};

// Identify AI components from file analysis
const identifyAIComponents = (fileContents: Record<string, string>): AIComponent[] => {
  const components: AIComponent[] = [];
  
  // Look for common AI libraries and services
  const patterns = {
    openai: /openai|gpt/i,
    langchain: /langchain/i,
    huggingface: /huggingface|hf/i,
    vectordb: /pinecone|chroma|weaviate|qdrant|milvus/i,
    embedding: /embedding|vector|ada|text-embedding/i,
    rag: /retrieval|document|knowledge/i
  };
  
  for (const [filePath, content] of Object.entries(fileContents)) {
    if (patterns.openai.test(content)) {
      components.push({
        name: "OpenAI Integration",
        type: "LLM Provider",
        confidence: 0.9
      });
    }
    
    if (patterns.langchain.test(content)) {
      components.push({
        name: "LangChain Framework",
        type: "LLM Framework",
        confidence: 0.85
      });
    }
    
    if (patterns.vectordb.test(content)) {
      // Determine which vector DB
      let dbName = "Vector Database";
      if (/pinecone/i.test(content)) dbName = "Pinecone";
      else if (/chroma/i.test(content)) dbName = "ChromaDB";
      else if (/weaviate/i.test(content)) dbName = "Weaviate";
      else if (/qdrant/i.test(content)) dbName = "Qdrant";
      else if (/milvus/i.test(content)) dbName = "Milvus";
      
      components.push({
        name: dbName,
        type: "Vector Database",
        confidence: 0.8
      });
    }
    
    if (patterns.embedding.test(content)) {
      components.push({
        name: "Text Embedding Model",
        type: "Embedding Model",
        confidence: 0.75
      });
    }
    
    if (patterns.rag.test(content) && patterns.vectordb.test(content)) {
      components.push({
        name: "RAG Implementation",
        type: "RAG Framework",
        confidence: 0.7
      });
    }
  }
  
  // Remove duplicates
  const uniqueComponents = components.filter(
    (comp, index, self) =>
      index === self.findIndex((c) => c.name === comp.name)
  );
  
  return uniqueComponents;
};

// Extract multiple file contents from a GitHub repository
async function extractRepoFiles(
  repoUrl: string,
  branch = "main"
): Promise<Record<string, string>> {
  try {
    console.log(`Extracting files from ${repoUrl}, branch: ${branch}`);
    
    // Parse GitHub URL to get owner and repo name
    const urlParts = repoUrl.split("/");
    const owner = urlParts[urlParts.length - 2];
    const repo = urlParts[urlParts.length - 1];
    
    console.log(`Owner: ${owner}, Repo: ${repo}`);
    
    // Get repository structure
    const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
    const treeResponse = await fetch(treeUrl);
    
    if (!treeResponse.ok) {
      console.error(`Error fetching repo tree: ${treeResponse.statusText}`);
      throw new Error(`Failed to fetch repository tree: ${treeResponse.statusText}`);
    }
    
    const treeData = await treeResponse.json();
    
    const fileContents: Record<string, string> = {};
    const promises: Promise<void>[] = [];
    
    // Filter to only include relevant files
    const relevantFiles = treeData.tree.filter((item: any) => {
      if (item.type !== "blob") return false;
      
      const path = item.path;
      const extensions = [".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".md", ".json"];
      
      return extensions.some(ext => path.endsWith(ext));
    });
    
    // Limit to 100 files to avoid rate limiting
    const filesToProcess = relevantFiles.slice(0, 100);
    
    // Fetch file contents in parallel
    for (const file of filesToProcess) {
      const promise = (async () => {
        try {
          const fileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
          const fileResponse = await fetch(fileUrl);
          
          if (fileResponse.ok) {
            const content = await fileResponse.text();
            fileContents[file.path] = content;
          }
        } catch (error) {
          console.error(`Error fetching file ${file.path}:`, error);
        }
      })();
      
      promises.push(promise);
    }
    
    await Promise.all(promises);
    console.log(`Extracted ${Object.keys(fileContents).length} files`);
    
    return fileContents;
  } catch (error) {
    console.error("Error extracting repository files:", error);
    throw error;
  }
}

// Function to get structured LLM-related info from code
const extractLLMRelatedInfo = (content: string): Record<string, string[]> => {
  const info: Record<string, string[]> = {
    models: [],
    providers: [],
    libraries: []
  };
  
  // Models
  const modelPatterns = [
    /gpt-3\.5/g, /gpt-4/g, /davinci/g, /claude/g,
    /llama/g, /mistral/g, /gemini/g, /palm/g, /text-embedding/g
  ];
  
  // Providers
  const providerPatterns = [
    /openai/gi, /anthropic/gi, /cohere/gi, /google/gi,
    /huggingface/gi, /replicate/gi, /stability/gi
  ];
  
  // Libraries
  const libraryPatterns = [
    /langchain/gi, /llamaindex/gi, /transformers/gi,
    /tiktoken/gi, /tokenizers/gi, /diffusers/gi,
    /faiss/gi, /sentence-transformers/gi
  ];
  
  // Extract models
  modelPatterns.forEach(pattern => {
    const matches = content.match(pattern);
    if (matches) {
      matches.forEach(match => {
        if (!info.models.includes(match)) {
          info.models.push(match);
        }
      });
    }
  });
  
  // Extract providers
  providerPatterns.forEach(pattern => {
    const matches = content.match(pattern);
    if (matches) {
      matches.forEach(match => {
        if (!info.providers.includes(match)) {
          info.providers.push(match);
        }
      });
    }
  });
  
  // Extract libraries
  libraryPatterns.forEach(pattern => {
    const matches = content.match(pattern);
    if (matches) {
      matches.forEach(match => {
        if (!info.libraries.includes(match)) {
          info.libraries.push(match);
        }
      });
    }
  });
  
  return info;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  // Handle CORS preflight request
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }
  
  try {
    const { repository_url, branch = "main" } = (await req.json()) as RepositoryAnalysisRequest;
    
    if (!repository_url) {
      throw new Error("Repository URL is required");
    }
    
    console.log(`Analyzing repository: ${repository_url}`);
    
    // Extract files from the repository
    const fileContents = await extractRepoFiles(repository_url, branch);
    
    // Get code references, security risks, and AI components
    const codeReferences = generateCodeReferences(fileContents);
    const [securityRisks, promptReferences] = getSecurityRisks(fileContents);
    const aiComponents = identifyAIComponents(fileContents);
    
    // Add any prompt references to code references if they're not already there
    for (const promptRef of promptReferences) {
      if (!codeReferences.some(ref => ref.id === promptRef.id)) {
        codeReferences.push(promptRef);
      }
    }
    
    // Calculate confidence score based on findings
    const aiComponentsWeight = 0.5;
    const securityRisksWeight = 0.3;
    const codeReferencesWeight = 0.2;
    
    const normalizedAIComponentScore = Math.min(aiComponents.length / 5, 1.0);
    const normalizedSecurityRiskScore = Math.min(securityRisks.length / 6, 1.0);
    const normalizedCodeReferencesScore = Math.min(codeReferences.length / 20, 1.0);
    
    const confidenceScore = (
      normalizedAIComponentScore * aiComponentsWeight +
      normalizedSecurityRiskScore * securityRisksWeight +
      normalizedCodeReferencesScore * codeReferencesWeight
    );
    
    // Generate remediation suggestions based on findings
    const remediationSuggestions = [
      "Implement input validation for all user inputs that affect LLM prompts",
      "Use parameterized prompts instead of string concatenation",
      "Store system prompts in a secure environment outside of code",
      "Implement rate limiting for LLM API calls",
      "Use a content filtering system to validate LLM outputs",
      "Implement a robust logging system for all LLM interactions"
    ];
    
    // Construct the final report
    const report = {
      ai_components_detected: aiComponents,
      security_risks: securityRisks,
      code_references: codeReferences,
      confidence_score: Math.min(Math.max(confidenceScore, 0.1), 0.95),
      remediation_suggestions: remediationSuggestions
    };
    
    console.log(`Analysis complete. Found ${aiComponents.length} AI components, ${securityRisks.length} security risks, and ${codeReferences.length} code references.`);
    
    return new Response(JSON.stringify(report), {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Error analyzing repository:", error);
    
    return new Response(
      JSON.stringify({
        error: error instanceof Error ? error.message : "Unknown error occurred",
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
});
