// Follow this setup guide to integrate the Deno runtime and the Supabase JS library with your project:
// https://docs.deno.com/runtime/manual/getting_started/setup_your_environment
// https://github.com/denoland/deno_std/tree/main/http/server.ts

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.4.0'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { encode, decode } from 'https://deno.land/std@0.168.0/encoding/base64.ts'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Fetch the OpenAI API key from the environment variable
const openaiApiKey = Deno.env.get('OPENAI_API_KEY')

// Simple in-memory cache (will reset on function restart)
const analysisCache = new Map();

// Add at the top of the file
type RepositoryContent = {
  repositoryName: string;
  files: RepositoryFile[];
};

type RepositoryFile = {
  path: string;
  content: string;
  extension: string;
};

type AIComponent = {
  name: string;
  type: string;
  sourcePath?: string;
};

// Update the CodeReference type with more specific categories
type ReferenceType = 
  // Model Operations
  | 'model_invocation'      // Direct LLM calls
  | 'model_config'          // Model configuration
  | 'prompt_definition'     // System/user prompts
  // Vector Operations
  | 'vector_operation'      // Vector DB operations
  | 'embedding_generation'  // Embedding creation
  // Security Related
  | 'credential_exposure'   // API keys, secrets
  | 'data_handling';        // Training data, fine-tuning

type CodeReference = {
  id: string;
  file: string;
  line: number;
  snippet: string;
  context: {
    before: string[];    // Lines before the match
    after: string[];     // Lines after the match
    scope?: string;      // Function/class scope if detectable
  };
  type: ReferenceType;
  confidence: number;
  verified: boolean;
  securityRisk?: boolean;
  llmUsage?: boolean;
};

type SecurityRisk = {
  risk: string;
  risk_name?: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  related_code_references?: string[];
  owasp_category?: {
    id: string;
    name: string;
    description: string;
  };
};

type AnalysisOptions = {
  systemPrompt?: string;
  debugMode?: boolean;
};

type AnalysisResult = {
  ai_components_detected: AIComponent[];
  security_risks: SecurityRisk[];
  code_references: CodeReference[];
  confidence_score: number;
  remediation_suggestions: string[];
  debug?: any;
};

// Initialize arrays with explicit types at declaration
const contextBuffer = [] as string[];
const codeReferences = [] as CodeReference[];
const recommendations = [] as string[];
const foundComponents = [] as AIComponent[];
const finalFiles = [] as RepositoryFile[];
const filePromises = [] as Promise<RepositoryFile | null>[];
const risks = [] as SecurityRisk[];
const uniqueComponents = [] as AIComponent[];

// Update pattern matching to be more precise
const aiPatterns = {
  modelInvocation: [
    // LangChain patterns (multiple versions)
    /from\s+langchain.*import.*Chat/i,
    /from\s+langchain.*import.*Model/i,
    /Chat\w+\s*\(/i,  // Catches ChatOpenAI, ChatAnthropic, etc.
    
    // Generic model operations
    /\.(generate|predict|create|complete|chat)/i,
    /model\.(invoke|call|run)/i,
    
    // Provider specific
    /(openai|anthropic|google|huggingface|cohere)/i
  ],
  vectorOperations: [
    // Vector DB operations
    /(pinecone|weaviate|qdrant|chroma|milvus)/i,
    /\.(query|search|similarity|nearest|upsert)/i,
    /vector.*?search/i,
    /embedding.*?search/i
  ],
  embeddingGeneration: [
    /\.embed\s*\(/i,
    /\.embedding\s*\(/i,
    /embeddings\.create\s*\(/i,
    /\.encode\s*\(/i
  ],
  promptDefinition: [
    /system_prompt|systemPrompt|SYSTEM_PROMPT/,
    /role:\s*['"]system['"],\s*content:/i,
    /messages:\s*\[\s*{\s*role:\s*['"]system['"]/i
  ],
  modelConfig: [
    /temperature\s*=\s*[0-9.]+/,           // Temperature setting
    /top_p\s*=\s*[0-9.]+/,                 // Top-p setting
    /frequency_penalty\s*=\s*[0-9.]+/,      // Frequency penalty
    /presence_penalty\s*=\s*[0-9.]+/        // Presence penalty
  ],
  credentialExposure: [
    /api[_-]?key\s*[:=]\s*['"`][^'"`]+['"`]/i,
    /secret\s*[:=]\s*['"`][^'"`]+['"`]/i,
    /password\s*[:=]\s*['"`][^'"`]+['"`]/i,
    /token\s*[:=]\s*['"`][^'"`]+['"`]/i
  ],
  dataHandling: [
    /\.fine_tune\s*\(/i,
    /\.train\s*\(/i,
    /training_data|train_data/i,
    /dataset\.load\s*\(/i
  ]
};

// Add type guard for repository content
function isValidRepositoryContent(content: any): content is RepositoryContent {
  return content && 
         !('error' in content) && 
         Array.isArray(content.files) &&
         typeof content.repositoryName === 'string';
}

// Define the serve function
serve(async (req) => {
  // This is needed if you're planning to invoke your function from a browser.
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Get the request body
    const requestData = await req.json();
    const { repositoryUrl, options = {} } = requestData;

    console.log(`Processing repository: ${repositoryUrl}`);

    // Set some reasonable limits to prevent abuse
    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: 'Repository URL is required' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 }
      );
    }

    // Check cache first to avoid repeated API calls
    const cacheKey = `${repositoryUrl}-${JSON.stringify(options)}`;
    if (analysisCache.has(cacheKey)) {
      console.log(`Returning cached analysis for ${repositoryUrl}`);
      const cachedResult = analysisCache.get(cacheKey);
      return new Response(
        JSON.stringify(cachedResult),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Enhanced repository scraping logic to handle nested structures
    const repositoryContent = await fetchRepositoryContent(repositoryUrl);
    
    if (repositoryContent.error) {
      return new Response(
        JSON.stringify({ error: repositoryContent.error }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
      );
    }

    // Scan and log files being processed
    const scanResults = scanRepositoryFiles(repositoryContent);
    console.log('Files scanned:', scanResults.scanned);
    console.log('Files skipped:', scanResults.skipped);
    
    if (scanResults.scanned.length === 0) {
      console.warn('No valid files found to scan in repository');
    }

    // Debug mode - include repository content in response if requested
    const debugMode = options.debugMode || false;
    let debugInfo = null;
    
    if (debugMode) {
      // Limit debug info to avoid huge responses
      if (isValidRepositoryContent(repositoryContent)) {
        debugInfo = {
          fileCount: repositoryContent.files.length,
          filePaths: repositoryContent.files.map(f => f.path).slice(0, 100),
          totalFilesFound: repositoryContent.files.length,
          repositoryName: repositoryContent.repositoryName,
          repoSize: JSON.stringify(repositoryContent).length,
        };
        console.log(`Debug info: ${JSON.stringify(debugInfo, null, 2)}`);
      }
    }

    // Extract components directly from repository content as a fallback mechanism
    const extractedComponents = extractComponentsFromRepository(repositoryContent);

    try {
      // Try to analyze with OpenAI first
      const analysisResult = await analyzeRepository(repositoryContent, options);
      
      // Post-process results to enhance
      const enhancedResult = postProcessAnalysisResults(analysisResult, repositoryContent);
      
      // Cache the result
      analysisCache.set(cacheKey, { ...enhancedResult, debug: debugInfo });
      
      // Return the result
      return new Response(
        JSON.stringify({ ...enhancedResult, debug: debugInfo }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    } catch (openaiError) {
      console.error('OpenAI analysis failed:', openaiError);
      
      // If OpenAI fails with a rate limit, use the fallback analysis
      if (openaiError.message && openaiError.message.includes('429')) {
        console.log('Rate limit hit, using fallback analysis mechanism');
        
        const fallbackResult = generateFallbackAnalysis(repositoryContent, extractedComponents);
        
        // Cache the fallback result
        analysisCache.set(cacheKey, { ...fallbackResult, debug: debugInfo, fallback: true });
        
        // Return the fallback result
        return new Response(
          JSON.stringify({ ...fallbackResult, debug: debugInfo, fallback: true }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
      
      // If it's not a rate limit issue, propagate the error
      throw openaiError;
    }
  } catch (error) {
    console.error('Error processing request:', error);
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
    );
  }
})

// Function to post-process analysis results to ensure all required data is present
function postProcessAnalysisResults(analysisResult, repositoryContent) {
  // Make a deep copy to avoid modifying the original
  const result = JSON.parse(JSON.stringify(analysisResult));
  
  // Ensure all fields exist
  if (!result.ai_components_detected) result.ai_components_detected = [];
  if (!result.security_risks) result.security_risks = [];
  if (!result.code_references) result.code_references = [];
  if (!result.remediation_suggestions) result.remediation_suggestions = [];
  if (typeof result.confidence_score !== 'number') result.confidence_score = 0.5;
  
  // Detect if this is an LLM repository
  const containsLLM = result.ai_components_detected.some(comp => {
    const name = (comp.name || '').toLowerCase();
    const type = (comp.type || '').toLowerCase();
    return name.includes('llm') || name.includes('gpt') || 
           name.includes('openai') || name.includes('anthropic') ||
           type.includes('llm') || type.includes('language model');
  });
  
  // If repository contains LLM components, ensure all six core risk types exist
  if (containsLLM) {
    ensureCoreRiskTypes(result);
  }
  
  // Find possible code references from the repository content and link them to risks
  if (result.code_references.length === 0) {
    result.code_references = findPotentialCodeReferences(repositoryContent);
  }

  // Enhanced linking of code references to risks - maintain existing structure
  result.security_risks = result.security_risks.map(risk => {
    const riskLower = (risk.risk || '').toLowerCase();
    const relatedRefs = result.code_references.filter(ref => {
      if (riskLower.includes('prompt injection') && ref.type === 'model_invocation') return true;
      if (riskLower.includes('data leakage') && ref.type === 'vector_operation') return true;
      if (riskLower.includes('hallucination') && ref.type === 'model_invocation') return true;
      if ((riskLower.includes('api key') || riskLower.includes('credential')) && ref.type === 'credential_exposure') return true;
      if (riskLower.includes('model poisoning') && ref.type === 'model_invocation') return true;
      if ((riskLower.includes('system prompt') || riskLower.includes('hardcoded prompt')) && ref.type === 'prompt_definition') return true;
      
      return false;
    });

    return {
      ...risk,
      related_code_references: relatedRefs.map(ref => ref.id),
      // Keep existing fields that frontend components expect
      risk_name: risk.risk_name || risk.risk,
      severity: risk.severity || 'medium',
      description: risk.description || '',
      owasp_category: risk.owasp_category
    };
  });
  
  // Generate remediation suggestions if none exist
  if (result.remediation_suggestions.length === 0) {
    result.remediation_suggestions = generateRecommendations(result.security_risks);
  }
  
  // Add OWASP categories to risks
  enhanceRisksWithOwaspCategories(result.security_risks);
  
  return result;
}

// Function to ensure all six core risk types are present
function ensureCoreRiskTypes(result) {
  // The six core risk types for any LLM application
  const coreRiskTypes = [
    {
      risk: "Prompt Injection Vulnerability",
      severity: "high",
      description: "User inputs could manipulate the LLM's behavior by altering its prompt instructions, potentially leading to unintended operations or information disclosure.",
      owasp_category: {
        id: "LLM01:2025",
        name: "Prompt Injection",
        description: "A vulnerability where user inputs manipulate the LLM's behavior by altering its prompts."
      }
    },
    {
      risk: "Data Leakage via LLM",
      severity: "medium",
      description: "LLM responses might inadvertently expose sensitive data or training information if proper data handling mechanisms are not in place.",
      owasp_category: {
        id: "LLM02:2025",
        name: "Sensitive Information Disclosure",
        description: "Risks involving the exposure of confidential data within the LLM or its applications."
      }
    },
    {
      risk: "Hallucination",
      severity: "medium",
      description: "The LLM may generate incorrect or fabricated information presented as factual, leading to misinformation or unreliable outputs.",
      owasp_category: {
        id: "LLM09:2025",
        name: "Misinformation",
        description: "The potential for LLMs to generate and propagate false or misleading information."
      }
    },
    {
      risk: "API Key Exposure",
      severity: "high",
      description: "API keys or credentials for LLM services may be exposed in the codebase, leading to unauthorized access or abuse.",
      owasp_category: {
        id: "LLM03:2025",
        name: "Supply Chain",
        description: "Vulnerabilities arising from the components and dependencies used in LLM development and deployment."
      }
    },
    {
      risk: "Model Poisoning",
      severity: "medium",
      description: "The LLM could be influenced by adversarial inputs or poisoned training data, affecting the quality and safety of outputs.",
      owasp_category: {
        id: "LLM04:2025",
        name: "Data and Model Poisoning",
        description: "Threats where malicious data is introduced during training, fine-tuning, or embedding processes."
      }
    },
    {
      risk: "Hardcoded System Prompts",
      severity: "medium",
      description: "Hardcoded system prompts in the codebase can reveal sensitive application logic or create vulnerabilities if they contain instructions that could be bypassed.",
      owasp_category: {
        id: "LLM07:2025",
        name: "System Prompt Leakage",
        description: "The exposure of system-level prompts that can reveal internal configurations or logic."
      }
    }
  ];
  
  // Check existing risks and add missing ones
  for (const coreRisk of coreRiskTypes) {
    const riskExists = result.security_risks.some(risk => 
      risk.risk && coreRisk.risk && 
      risk.risk.toLowerCase().includes(coreRisk.risk.toLowerCase())
    );
    
    if (!riskExists) {
      // Add with empty related_code_references that will be filled later
      result.security_risks.push({
        ...coreRisk,
        related_code_references: []
      });
    } else {
      // Update existing risk to ensure it has OWASP category
      const existingRisk = result.security_risks.find(risk => 
        risk.risk && coreRisk.risk && 
        risk.risk.toLowerCase().includes(coreRisk.risk.toLowerCase())
      );
      
      if (existingRisk && !existingRisk.owasp_category) {
        existingRisk.owasp_category = coreRisk.owasp_category;
      }
      
      // Ensure related_code_references exists
      if (!existingRisk.related_code_references) {
        existingRisk.related_code_references = [];
      }
    }
  }
}

// Function to enhance risks with OWASP categories
function enhanceRisksWithOwaspCategories(securityRisks) {
  // OWASP LLM Top 10 category mapping
  const owaspCategoryMap = {
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
    // Common aliases
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
    "hardcoded system prompts": {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    }
  };
  
  // Apply OWASP categories to each risk
  for (const risk of securityRisks) {
    if (!risk.owasp_category && risk.risk) {
      const riskLower = risk.risk.toLowerCase();
      
      // Find matching category
      for (const [key, category] of Object.entries(owaspCategoryMap)) {
        if (riskLower.includes(key)) {
          risk.owasp_category = category;
          break;
        }
      }
      
      // Default to Improper Output Handling if no match found
      if (!risk.owasp_category) {
        risk.owasp_category = owaspCategoryMap["improper output handling"];
      }
    }
  }
}

// Function to find potential code references in repository
function findPotentialCodeReferences(repositoryContent: RepositoryContent) {
  const codeReferences = [] as CodeReference[];
  let refId = 1;  // Initialize reference ID counter
  console.log('Starting code reference scan...');

  for (const file of repositoryContent.files) {
    // Log file being processed
    console.log(`Processing file: ${file.path}`);

    // Skip binary or extremely large files
    if (!file.content || file.content.length > 100000) {
      console.log(`Skipping file (empty/large): ${file.path}`);
      continue;
    }

    // Focus on code files
    const ext = file.path.toLowerCase().substring(file.path.lastIndexOf('.'));
    const isCodeFile = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb']
      .includes(ext);

    if (!isCodeFile) {
      console.log(`Skipping non-code file: ${file.path}`);
      continue;
    }

    console.log(`Scanning file: ${file.path}`);
    const lines = file.content.split('\n');
    let contextBuffer = []; // Store previous lines for context
    
    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const lowerLine = line.toLowerCase();
      
      // Update context buffer
      contextBuffer.push(line);
      if (contextBuffer.length > 5) contextBuffer.shift();
      
      // Check for actual AI component usage (not just imports)
      const hasModelInvocation = aiPatterns.modelInvocation.some(pattern => pattern.test(line));
      const hasVectorOperation = aiPatterns.vectorOperations.some(pattern => pattern.test(pattern));
      const hasEmbeddingGeneration = aiPatterns.embeddingGeneration.some(pattern => pattern.test(line));
      const hasPromptDefinition = aiPatterns.promptDefinition.some(pattern => pattern.test(line));
      const hasModelConfig = aiPatterns.modelConfig.some(pattern => pattern.test(line));
      const hasCredentialExposure = aiPatterns.credentialExposure.some(pattern => pattern.test(line));
      const hasDataHandling = aiPatterns.dataHandling.some(pattern => pattern.test(line));
      
      // Calculate confidence based on context
      let confidence = 0;
      let referenceType: ReferenceType | null = null;
      
      if (hasModelInvocation) {
        confidence = 0.9;
        referenceType = 'model_invocation';
      } else if (hasVectorOperation) {
        confidence = 0.8;
        referenceType = 'vector_operation';
      } else if (hasEmbeddingGeneration) {
        confidence = 0.7;
        referenceType = 'embedding_generation';
      } else if (hasPromptDefinition) {
        confidence = 0.8;
        referenceType = 'prompt_definition';
      } else if (hasModelConfig) {
        confidence = 0.7;
        referenceType = 'model_config';
      } else if (hasCredentialExposure) {
        confidence = 0.95;
        referenceType = 'credential_exposure';
      } else if (hasDataHandling) {
        confidence = 0.9;
        referenceType = 'data_handling';
      }
      
      // Only add high-confidence references
      if (confidence > 0.6) {
        const afterLines = lines.slice(index + 1, index + 1 + 3);
        
        codeReferences.push({
          id: `ref_${refId++}`,
          file: file.path,
          line: lineNumber,
          snippet: line.trim(),
          context: {
            before: [...contextBuffer],
            after: afterLines,
            scope: detectScope(lines, lineNumber)
          },
          type: referenceType,
          confidence: confidence,
          verified: true
        });
      }
      
      // Special handling for credential exposure (higher precision)
      if (lowerLine.match(/(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"`][^'"`]+['"`]/i)) {
        // Skip if it's in an enum or constant definition
        if (lowerLine.match(/enum\s+|const\s+.*?=\s*{/i)) {
          return;
        }
        // Skip if it's a template/example
        if (lowerLine.match(/example|template|your.*?here|placeholder/i)) {
          return;
        }
        // Skip if it's referencing environment variables
        if (lowerLine.match(/process\.env|os\.environ|getenv|config\./i)) {
          return;
        }
        // Only then add as credential exposure
        codeReferences.push({
          id: `ref_${refId++}`,
          file: file.path,
          line: lineNumber,
          snippet: line.trim(),
          context: {
            before: [...contextBuffer],
            after: [],
            scope: detectScope(lines, lineNumber)
          },
          type: 'credential_exposure',
          confidence: 0.95,
          verified: true
        });
      }
    });
  }
  
  // Post-process to remove duplicates and near-duplicates
  return deduplicateReferences(codeReferences);
}

// Helper function to deduplicate references
function deduplicateReferences(references) {
  const seen = new Set();
  return references.filter(ref => {
    // Create a signature based on file, type, and normalized snippet
    const signature = `${ref.file}:${ref.type}:${normalizeSnippet(ref.snippet)}`;
    if (seen.has(signature)) return false;
    seen.add(signature);
    return true;
  });
}

// Helper to normalize code snippets for comparison
function normalizeSnippet(snippet) {
  return snippet
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/['"`]/g, '"')
    .trim();
}

// Function to link code references to security risks
function linkCodeReferencesToRisks(result) {
  // Ensure code references exist
  if (!result.code_references || result.code_references.length === 0) {
    return;
  }
  
  // Link each risk to relevant code references
  for (const risk of result.security_risks) {
    if (!risk.related_code_references) {
      risk.related_code_references = [];
    }
    
    // Match code references to risks based on risk type
    const riskLower = risk.risk.toLowerCase();
    
    for (const ref of result.code_references) {
      // Link based on risk type
      if (riskLower.includes('prompt injection') && ref.model_invocation) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
      else if (riskLower.includes('data leakage') && ref.vector_operation) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
      else if (riskLower.includes('hallucination') && ref.model_invocation) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
      else if ((riskLower.includes('api key') || riskLower.includes('credential')) && ref.credential_exposure) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
      else if (riskLower.includes('model poisoning') && ref.model_invocation) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
      else if ((riskLower.includes('system prompt') || riskLower.includes('hardcoded prompt')) && ref.prompt_definition) {
        if (!risk.related_code_references.includes(ref.id)) {
          risk.related_code_references.push(ref.id);
        }
      }
    }
  }
}

// Function to generate remediation recommendations
function generateRecommendations(securityRisks) {
  const recommendations = [];
  
  // Add specific recommendations based on risk types
  for (const risk of securityRisks) {
    const riskLower = risk.risk.toLowerCase();
    
    if (riskLower.includes('prompt injection')) {
      recommendations.push("Sanitize and validate all user inputs before including them in LLM prompts");
      recommendations.push("Use input formatting techniques to clearly separate instructions from user input");
      recommendations.push("Consider implementing a prompt validation layer to detect potential injection attempts");
    }
    else if (riskLower.includes('data leakage')) {
      recommendations.push("Implement proper data filtering and sanitization before sending to LLM");
      recommendations.push("Use a retrieval filtering mechanism to prevent sensitive data from being included in context");
      recommendations.push("Consider implementing LLM guardrails to detect and prevent potential data leakage");
    }
    else if (riskLower.includes('hallucination')) {
      recommendations.push("Implement fact-checking mechanisms for critical information");
      recommendations.push("Set appropriate model parameters to reduce hallucination (lower temperature, higher top_p)");
      recommendations.push("Consider source attribution in outputs to help users validate information");
    }
    else if (riskLower.includes('api key') || riskLower.includes('credential')) {
      recommendations.push("Replace hardcoded API keys and credentials with environment variables or a secure secret management solution");
      recommendations.push("Implement a secrets manager or environment variable solution for credential management");
    }
    else if (riskLower.includes('model poisoning')) {
      recommendations.push("Validate and sanitize all training data before fine-tuning models");
      recommendations.push("Implement monitoring for unexpected model behavior");
      recommendations.push("Consider using models from trusted providers with established safety measures");
    }
    else if (riskLower.includes('system prompt') || riskLower.includes('hardcoded prompt')) {
      recommendations.push("Store system prompts in a secure configuration system rather than hardcoding them");
      recommendations.push("Keep prompt templates separate from the application logic");
      recommendations.push("Consider encrypting sensitive prompt elements");
    }
  }
  
  // Add general recommendations
  if (!recommendations.some(r => r.includes("rate limiting"))) {
    recommendations.push("Implement rate limiting for all AI API calls");
  }
  
  if (!recommendations.some(r => r.includes("input validation"))) {
    recommendations.push("Add input validation and sanitization for all user inputs used in AI contexts");
  }
  
  // Deduplicate recommendations
  return [...new Set(recommendations)];
}

// Function to analyze a repository using OpenAI
async function analyzeRepository(repositoryContent, options = {}) {
  if (!openaiApiKey) {
    throw new Error('OpenAI API key is not configured.');
  }

  const systemPrompt = options.systemPrompt || `Analyze the GitHub repository and provide insights about AI components and security risks.`;
  
  // Analyze repository to identify files with metadata (requirements.txt, package.json)
  const metadataFiles = identifyMetadataFiles(repositoryContent.files);
  console.log(`Found ${metadataFiles.length} metadata files`);
  
  // Extract AI components from metadata files (pre-processing)
  const aiComponentsFromMetadata = extractAIComponentsFromMetadata(metadataFiles);
  console.log(`Pre-extracted ${aiComponentsFromMetadata.length} AI components from metadata files`);

  // Prepare files for OpenAI analysis - prioritize important files and limit total size
  const filesToAnalyze = prioritizeFilesForAnalysis(repositoryContent.files, aiComponentsFromMetadata);
  
  // Prepare the messages for OpenAI
  const messages = [
    {
      "role": "system",
      "content": systemPrompt
    },
    {
      "role": "user",
      "content": formatRepositoryForAnalysis(repositoryContent.repositoryName, filesToAnalyze, aiComponentsFromMetadata)
    }
  ];

  try {
    // Call OpenAI API with proper error handling and retries
    const response = await fetchWithRetry('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openaiApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: "gpt-4-0125-preview", // Using the preview model as it's often less busy
        messages: messages,
        temperature: 0.2,
        max_tokens: 4000,
        response_format: { type: "json_object" }
      })
    }, 2); // Retry up to 2 times

    if (!response.ok) {
      const errorData = await response.text();
      console.error("OpenAI API error:", errorData);
      
      // Check for rate limit error (429)
      if (response.status === 429) {
        throw new Error(`OpenAI API error: 429`);
      }
      
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const result = await response.json();
    
    try {
      // Parse the content as JSON
      const analysisResult = JSON.parse(result.choices[0].message.content);
      
      // Fill in pre-extracted AI components if OpenAI didn't find any
      if (!analysisResult.ai_components_detected || analysisResult.ai_components_detected.length === 0) {
        analysisResult.ai_components_detected = aiComponentsFromMetadata.map(component => ({
          name: component.name,
          type: component.type || "Library",
          confidence: 0.9
        }));
      }
      
      return analysisResult;
    } catch (error) {
      console.error("Error parsing OpenAI response:", error);
      throw new Error("Error parsing the analysis result from OpenAI.");
    }
  } catch (error) {
    console.error("Error in OpenAI API call:", error);
    throw error; // Propagate the error to be handled by the caller
  }
}

// Helper function for fetch with retry
async function fetchWithRetry(url, options, retries = 3, backoff = 300) {
  try {
    return await fetch(url, options);
  } catch (err) {
    if (retries <= 0) {
      throw err;
    }
    
    // Wait before retrying
    await new Promise(resolve => setTimeout(resolve, backoff));
    
    // Retry with exponential backoff
    return fetchWithRetry(url, options, retries - 1, backoff * 2);
  }
}

// Fallback analysis when OpenAI is not available
function generateFallbackAnalysis(repositoryContent, extractedComponents) {
  console.log('Generating fallback analysis');
  
  // Extract metadata files and AI components
  const metadataFiles = identifyMetadataFiles(repositoryContent.files);
  const aiComponentsFromMetadata = extractAIComponentsFromMetadata(metadataFiles);
  
  // Find code references using direct pattern matching
  const codeReferences = findCodeReferences(repositoryContent.files, aiComponentsFromMetadata);
  
  // Identify security risks based on components and patterns
  const securityRisks = identifySecurityRisks(repositoryContent.files, aiComponentsFromMetadata, codeReferences);
  
  // Post-process to add OWASP categories
  enhanceRisksWithOwaspCategories(securityRisks);
  
  // Ensure all core risks are present if LLM components are detected
  const hasLLM = aiComponentsFromMetadata.some(comp => 
    comp.name.toLowerCase() === 'openai' || 
    comp.name.toLowerCase().includes('llm') ||
    comp.name.toLowerCase().includes('gpt') ||
    comp.name.toLowerCase() === 'langchain'
  );
  
  const analysisResult = {
    ai_components_detected: aiComponentsFromMetadata.map(component => ({
      name: component.name,
      type: component.type || "Library",
      confidence: 0.85
    })),
    security_risks: securityRisks,
    code_references: codeReferences,
    confidence_score: 0.75,
    remediation_suggestions: generateRecommendations(securityRisks),
    analysis_method: "Pattern-based (OpenAI API unavailable)"
  };
  
  // Make sure all fundamental LLM risks are present if LLM components are detected
  if (hasLLM) {
    ensureCoreRiskTypes(analysisResult);
    linkCodeReferencesToRisks(analysisResult);
  }
  
  return analysisResult;
}

// Extract components directly from repository
function extractComponentsFromRepository(repositoryContent) {
  const metadataFiles = identifyMetadataFiles(repositoryContent.files);
  return extractAIComponentsFromMetadata(metadataFiles);
}

// Function to find code references using pattern matching
function findCodeReferences(files, aiComponents) {
  const codeReferences = [];
  let refId = 1;
  
  // Get names of AI components to search for
  const componentNames = aiComponents.map(comp => comp.name.toLowerCase());
  
  files.forEach(file => {
    // Focus on Python, JavaScript, and other code files
    if (!['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb'].includes(file.extension)) {
      return;
    }
    
    const lines = file.content.split('\n');
    
    lines.forEach((line, lineIndex) => {
      const lineNumber = lineIndex + 1;
      
      // Check for imports or usage of AI components
      for (const componentName of componentNames) {
        const lowerLine = line.toLowerCase();
        
        // Python-style imports
        if (file.extension === '.py' && 
            (lowerLine.includes(`import ${componentName}`) || 
             lowerLine.includes(`from ${componentName}`) ||
             lowerLine.match(new RegExp(`${componentName}\\.\\w+`)))) {
          
          codeReferences.push({
            id: `ref_${refId++}`,
            file: file.path,
            line: lineNumber,
            snippet: line.trim(),
            context: {
              before: [],
              after: [],
              scope: detectScope(lines, lineNumber)
            },
            type: 'model_invocation',
            confidence: 0.9,
            verified: true
          });
        }
        
        // JavaScript/TypeScript imports
        if (['.js', '.ts', '.jsx', '.tsx'].includes(file.extension) &&
            (lowerLine.includes(`import`) && lowerLine.includes(componentName) ||
             lowerLine.includes(`require`) && lowerLine.includes(componentName))) {
          
          codeReferences.push({
            id: `ref_${refId++}`,
            file: file.path,
            line: lineNumber,
            snippet: line.trim(),
            context: {
              before: [],
              after: [],
              scope: detectScope(lines, lineNumber)
            },
            type: 'model_invocation',
            confidence: 0.9,
            verified: true
          });
        }
        
        // Java imports
        if (file.extension === '.java' &&
            lowerLine.includes(`import`) && lowerLine.includes(componentName)) {
          
          codeReferences.push({
            id: `ref_${refId++}`,
            file: file.path,
            line: lineNumber,
            snippet: line.trim(),
            context: {
              before: [],
              after: [],
              scope: detectScope(lines, lineNumber)
            },
            type: 'model_invocation',
            confidence: 0.9,
            verified: true
          });
        }
      }
      
      // Look for API keys and credentials
      if (line.match(/api[_-]?key|secret|password|credential|token/i) && 
          line.match(/=|\:|const|let|var/) &&
          !line.match(/process\.env|os\.environ|getenv|System\.getenv/)) {
        
        codeReferences.push({
          id: `ref_${refId++}`,
          file: file.path,
          line: lineNumber,
          snippet: line.trim(),
          context: {
            before: [],
            after: [],
            scope: detectScope(lines, lineNumber)
          },
          type: 'credential_exposure',
          confidence: 0.95,
          verified: true,
          securityRisk: true
        });
      }
      
      // Look for LLM-related code (prompts, completion calls, etc.)
      if (line.match(/prompt|completion|chat|llm|gpt|generate|token/i) && 
          (line.match(/openai/i) || line.match(/anthropic/i) || line.match(/generate_text/i) || line.match(/llm\./i))) {
        
        codeReferences.push({
          id: `ref_${refId++}`,
          file: file.path,
          line: lineNumber,
          snippet: line.trim(),
          context: {
            before: [],
            after: [],
            scope: detectScope(lines, lineNumber)
          },
          type: 'model_invocation',
          confidence: 0.9,
          verified: true,
          llmUsage: true
        });
      }
    });
  });
  
  return codeReferences;
}

// Identify security risks based on components and patterns
function identifySecurityRisks(files, aiComponents, codeReferences) {
  const risks = [];
  
  // Check for hardcoded credentials
  const credentialRefs = codeReferences.filter(ref => ref.securityRisk);
  if (credentialRefs.length > 0) {
    risks.push({
      risk: "Hardcoded Credentials",
      severity: "high",
      description: "Potential API keys or credentials found in code",
      related_code_references: credentialRefs.map(ref => ref.id)
    });
  }
  
  // Check for LLM usage
  const hasLLM = aiComponents.some(comp => 
    comp.name.toLowerCase() === 'openai' || 
    comp.name.toLowerCase().includes('llm') ||
    comp.name.toLowerCase().includes('gpt') ||
    comp.name.toLowerCase() === 'langchain' ||
    comp.name.toLowerCase() === 'anthropic' ||
    comp.name.toLowerCase() === 'claude' ||
    comp.type?.toLowerCase().includes('llm')
  );
  
  const llmRefs = codeReferences.filter(ref => ref.llmUsage);
  
  // Add fundamental LLM risks if LLM is detected
  if (hasLLM || llmRefs.length > 0) {
    // Add prompt injection risk
    risks.push({
      risk: "Prompt Injection Vulnerability",
      severity: "high",
      description: "LLM systems may be vulnerable to prompt injection attacks where user input can manipulate the model's behavior by overriding previous instructions.",
      related_code_references: llmRefs.map(ref => ref.id)
    });
    
    // Add jailbreak risk
    risks.push({
      risk: "LLM Jailbreak Vulnerability",
      severity: "medium",
      description: "LLM implementations may be vulnerable to jailbreak techniques that bypass safety guardrails and content filters.",
      related_code_references: llmRefs.map(ref => ref.id)
    });
    
    // Add hallucination risk
    risks.push({
      risk: "Potential for Hallucinations",
      severity: "medium",
      description: "Language models can generate plausible-sounding but false or misleading information, which may be presented as factual to users.",
      related_code_references: llmRefs.map(ref => ref.id)
    });
  }
  
  // Check for RAG components alongside LLM usage
  const hasVectorDB = aiComponents.some(comp => 
    ['faiss', 'pinecone', 'weaviate', 'chromadb', 'qdrant'].includes(comp.name.toLowerCase()) ||
    comp.type?.toLowerCase().includes('vector')
  );
  
  const hasEmbeddings = aiComponents.some(comp => 
    comp.name.toLowerCase().includes('embedding') ||
    comp.name.toLowerCase() === 'sentence-transformers'
  );
  
  // If we have LLM + (Vector DB or Embeddings), flag RAG-related risks
  if (hasLLM && (hasVectorDB || hasEmbeddings)) {
    risks.push({
      risk: "Potential for Data Leakage via LLM",
      severity: "medium",
      description: "RAG components detected alongside LLM usage, which may present data leakage risks if not properly configured",
      related_code_references: codeReferences
        .filter(ref => ref.snippet.toLowerCase().includes('embed') || ref.snippet.toLowerCase().includes('vector'))
        .map(ref => ref.id)
    });
  }
  
  return risks;
}

// Identify metadata files like requirements.txt, package.json, etc.
function identifyMetadataFiles(files) {
  return files.filter(file => {
    const fileName = file.path.split('/').pop().toLowerCase();
    return (
      fileName === 'requirements.txt' || 
      fileName === 'package.json' ||
      fileName === 'pipfile' ||
      fileName === 'pipfile.lock' ||
      fileName === 'setup.py'
    );
  });
}

// Extract AI components from metadata files
function extractAIComponentsFromMetadata(metadataFiles) {
  const aiLibraries = [
    // Python
    { name: 'openai', type: 'LLM API' },
    { name: 'langchain', type: 'LLM Framework' },
    { name: 'transformers', type: 'ML Framework' },
    { name: 'huggingface', type: 'ML Hub' },
    { name: 'sentence-transformers', type: 'Embedding' },
    { name: 'pytorch', type: 'ML Framework' },
    { name: 'tensorflow', type: 'ML Framework' },
    { name: 'keras', type: 'ML Framework' },
    { name: 'scikit-learn', type: 'ML Framework' },
    { name: 'scipy', type: 'Scientific Computing' },
    { name: 'numpy', type: 'Numerical Computing' },
    { name: 'pandas', type: 'Data Analysis' },
    { name: 'matplotlib', type: 'Data Visualization' },
    { name: 'spacy', type: 'NLP Library' },
    { name: 'nltk', type: 'NLP Library' },
    { name: 'gensim', type: 'NLP Library' },
    { name: 'anthropic', type: 'LLM API' },
    { name: 'llama-cpp-python', type: 'Local LLM' },
    { name: 'llama-index', type: 'RAG Framework' },
    // Vector databases
    { name: 'faiss', type: 'Vector Database' },
    { name: 'faiss-cpu', type: 'Vector Database' },
    { name: 'faiss-gpu', type: 'Vector Database' },
    { name: 'pinecone', type: 'Vector Database' },
    { name: 'pinecone-client', type: 'Vector Database' },
    { name: 'weaviate', type: 'Vector Database' },
    { name: 'weaviate-client', type: 'Vector Database' },
    { name: 'chromadb', type: 'Vector Database' },
    { name: 'qdrant', type: 'Vector Database' },
    { name: 'qdrant-client', type: 'Vector Database' },
    // JavaScript
    { name: '@openai/api', type: 'LLM API' },
    { name: 'openai', type: 'LLM API' }, // JS version
    { name: 'langchainjs', type: 'LLM Framework' },
    { name: 'langchain', type: 'LLM Framework' }, // JS version
    { name: '@langchain/openai', type: 'LLM Framework' },
    { name: '@huggingface/inference', type: 'ML API' },
    { name: 'tensorflow.js', type: 'ML Framework' },
    { name: '@tensorflow/tfjs', type: 'ML Framework' },
    { name: 'ml5.js', type: 'ML Framework' },
    { name: 'brain.js', type: 'ML Framework' },
    { name: '@anthropic-ai/sdk', type: 'LLM API' },
    { name: 'anthropic', type: 'LLM API' }, // JS version
  ];

  const foundComponents = [];

  // Process each metadata file
  metadataFiles.forEach(file => {
    const fileName = file.path.split('/').pop().toLowerCase();
    
    if (fileName === 'requirements.txt' || fileName === 'pipfile' || fileName === 'setup.py') {
      // Process Python dependencies
      console.log(`Processing Python dependencies in ${file.path}`);
      
      const lines = file.content.split('\n');
      lines.forEach(line => {
        // Remove comments and trim
        const cleanLine = line.split('#')[0].trim();
        
        if (cleanLine) {
          // Extract package name (ignore version specification)
          let packageName = cleanLine.split(/[=<>~!]/)[0].trim().toLowerCase();
          
          // Handle extras like package[extra]
          packageName = packageName.split('[')[0];
          
          // Check for matches
          const match = aiLibraries.find(lib => packageName === lib.name.toLowerCase());
          
          if (match) {
            console.log(`Found AI library in ${file.path}: ${packageName}`);
            foundComponents.push({
              name: match.name,
              type: match.type,
              sourcePath: file.path
            });
          }
        }
      });
    } else if (fileName === 'package.json') {
      // Process JavaScript dependencies
      try {
        const packageJson = JSON.parse(file.content);
        
        // Combine dependencies and devDependencies
        const allDependencies = { 
          ...(packageJson.dependencies || {}), 
          ...(packageJson.devDependencies || {}) 
        };
        
        for (const [packageName, version] of Object.entries(allDependencies)) {
          const match = aiLibraries.find(lib => packageName === lib.name || packageName.includes(lib.name.toLowerCase()));
          
          if (match) {
            console.log(`Found AI library in ${file.path}: ${packageName}`);
            foundComponents.push({
              name: match.name,
              type: match.type,
              sourcePath: file.path
            });
          }
        }
      } catch (error) {
        console.error(`Error parsing package.json at ${file.path}:`, error);
      }
    }
  });

  // Remove duplicates
  const uniqueComponents = [];
  const seenComponents = new Set();
  
  foundComponents.forEach(component => {
    const key = component.name.toLowerCase();
    if (!seenComponents.has(key)) {
      seenComponents.add(key);
      uniqueComponents.push(component);
    }
  });

  console.log(`Extracted ${uniqueComponents.length} unique AI components from metadata files`);
  return uniqueComponents;
}

// Prioritize files for analysis
function prioritizeFilesForAnalysis(files, aiComponentsFromMetadata) {
  // First, copy the files to avoid modifying the original array
  const allFiles = [...files];
  
  // Sort files by importance
  const sortedFiles = allFiles.sort((a, b) => {
    // First prioritize metadata files
    const aIsMetadata = isMetadataFile(a.path);
    const bIsMetadata = isMetadataFile(b.path);
    
    if (aIsMetadata && !bIsMetadata) return -1;
    if (!aIsMetadata && bIsMetadata) return 1;
    
    // Then prioritize files that might contain AI components
    const aHasAIImport = mightContainAIImports(a);
    const bHasAIImport = mightContainAIImports(b);
    
    if (aHasAIImport && !bHasAIImport) return -1;
    if (!aHasAIImport && bHasAIImport) return 1;
    
    // Then prioritize by file size (smaller files first to maximize diversity)
    return a.content.length - b.content.length;
  });
  
  // Extract information about AI components from metadata
  const aiLibraryNames = aiComponentsFromMetadata.map(comp => comp.name.toLowerCase());
  
  // Re-prioritize code files that might import the detected AI libraries
  const reprioritizedFiles = sortedFiles.map(file => {
    // Check if this file imports any of the detected AI libraries
    const importsPriority = checkForSpecificImports(file, aiLibraryNames);
    return { file, importsPriority };
  });
  
  // Sort by the importsPriority (higher first)
  reprioritizedFiles.sort((a, b) => b.importsPriority - a.importsPriority);
  
  // Get the final list of files, ensuring metadata files are first
  const metadataFiles = reprioritizedFiles
    .filter(item => isMetadataFile(item.file.path))
    .map(item => item.file);
  
  const nonMetadataFiles = reprioritizedFiles
    .filter(item => !isMetadataFile(item.file.path))
    .map(item => item.file);
  
  // Combine and limit to a reasonable size for analysis
  const combinedFiles = [...metadataFiles, ...nonMetadataFiles];
  
  // Limit total content size to avoid OpenAI token limits
  const maxTokens = 50000; // Approximate token limit
  const estimatedTokensPerChar = 0.25; // Rough estimate
  
  let totalSize = 0;
  const finalFiles = [];
  
  for (const file of combinedFiles) {
    const estimatedTokens = file.content.length * estimatedTokensPerChar;
    
    if (totalSize + estimatedTokens <= maxTokens) {
      finalFiles.push(file);
      totalSize += estimatedTokens;
    } else {
      // If we can't fit the entire file, include a truncated version or just the path
      const truncatedContent = file.content.substring(0, Math.floor((maxTokens - totalSize) / estimatedTokensPerChar));
      if (truncatedContent.length > 100) {
        finalFiles.push({
          path: file.path,
          content: truncatedContent + '... [content truncated for size]',
          extension: file.extension
        });
      } else {
        // Just include the path if we can't fit a meaningful portion
        finalFiles.push({
          path: file.path,
          content: '[content omitted for size]',
          extension: file.extension
        });
      }
      break;
    }
  }
  
  console.log(`Prioritized ${finalFiles.length} files for analysis out of ${files.length} total files`);
  return finalFiles;
}

// Helper function to check if file is a metadata file
function isMetadataFile(path) {
  const fileName = path.split('/').pop().toLowerCase();
  return (
    fileName === 'requirements.txt' || 
    fileName === 'package.json' ||
    fileName === 'pipfile' ||
    fileName === 'pipfile.lock' ||
    fileName === 'setup.py'
  );
}

// Helper function to check if a file might contain AI component imports
function mightContainAIImports(file) {
  const content = file.content.toLowerCase();
  
  // Check for common AI imports
  const aiKeywords = [
    'import openai', 'from openai', 
    'import langchain', 'from langchain',
    'import transformers', 'from transformers',
    'import huggingface', 'from huggingface',
    'import tensorflow', 'from tensorflow',
    'import torch', 'from torch',
    'import keras', 'from keras',
    'import sklearn', 'from sklearn',
    'import numpy', 'from numpy',
    'import pandas', 'from pandas',
    'import anthropic', 'from anthropic',
    'llm', 'gpt', 'bert', 'transformer',
    'embedding', 'vector', 'faiss', 'pinecone', 'weaviate', 'chromadb', 'qdrant'
  ];
  
  return aiKeywords.some(keyword => content.includes(keyword));
}

// Check for specific import patterns and assign a priority score
function checkForSpecificImports(file, aiLibraryNames) {
  if (!file.content) return 0;
  
  const content = file.content.toLowerCase();
  let importScore = 0;
  
  // For Python files
  if (file.extension === '.py') {
    // Check for specific imports of AI libraries
    for (const libName of aiLibraryNames) {
      const patterns = [
        `import ${libName}`,
        `from ${libName}`,
        `import ${libName}.`,
        `from ${libName}.`
      ];
      
      for (const pattern of patterns) {
        if (content.includes(pattern)) {
          importScore += 10;
          console.log(`Found import of ${libName} in ${file.path}`);
        }
      }
    }
  }
  
  // For JavaScript/TypeScript files
  if (['.js', '.ts', '.jsx', '.tsx'].includes(file.extension)) {
    // Check for import statements
    for (const libName of aiLibraryNames) {
      const patterns = [
        `import ${libName}`,
        `from '${libName}`,
        `from "${libName}`,
        `require('${libName}`,
        `require("${libName}`
      ];
      
      for (const pattern of patterns) {
        if (content.includes(pattern)) {
          importScore += 10;
          console.log(`Found import of ${libName} in ${file.path}`);
        }
      }
    }
  }
  
  return importScore;
}

// Format the repository data for OpenAI analysis
function formatRepositoryForAnalysis(repositoryName, files, preExtractedComponents) {
  let prompt = `Please analyze the GitHub repository "${repositoryName}" for AI components and security risks. The repository has ${files.length} files. I'll provide the content of key files below.\n\n`;
  
  // Add information about pre-extracted components
  if (preExtractedComponents.length > 0) {
    prompt += `Pre-extracted AI components from dependency files:\n`;
    preExtractedComponents.forEach(comp => {
      prompt += `- ${comp.name} (${comp.type}) found in ${comp.sourcePath}\n`;
    });
    prompt += `\n`;
  }
  
  // Add file contents
  files.forEach(file => {
    prompt += `=== FILE: ${file.path} ===\n${file.content}\n\n`;
  });
  
  prompt += `Based on the repository content above, please provide a JSON response with the following structure:
{
  "ai_components_detected": [
    { "name": "component_name", "type": "component_type", "confidence": 0.95 }
  ],
  "security_risks": [
    { 
      "risk": "risk_name", 
      "severity": "high/medium/low", 
      "description": "Description of the risk",
      "related_code_references": ["ref_id1", "ref_id2"],
      "owasp_category": {
        "id": "LLMxx:2025",  // Use ONLY OWASP LLM Top 10 2025 categories
        "name": "Category Name",
        "description": "Category description"
      }
    }
  ],
  "code_references": [
    { 
      "id": "unique_id", 
      "file": "file_path", 
      "line": 42, 
      "snippet": "code_snippet", 
      "verified": true
    }
  ],
  "confidence_score": 0.85,
  "remediation_suggestions": [
    "Suggestion 1",
    "Suggestion 2"
  ]
}

Please be specific about AI components you identify, focusing on:
1. LLM APIs (OpenAI, Claude, etc.)
2. AI frameworks (LangChain, HuggingFace, etc.)
3. Vector databases (FAISS, Pinecone, etc.)
4. Embedding generation
5. RAG components

IMPORTANT: Always include these fundamental security risks when LLM components are detected:
1. Prompt Injection Vulnerability - user input potentially manipulating LLM behavior
2. LLM Jailbreak Vulnerability - potential for bypassing safety guardrails
3. Potential for Hallucinations - risk of presenting false information as factual

For code_references, include only actual code you can verify from the provided files.

IMPORTANT: For ALL security risks, use ONLY these OWASP LLM categories:
- LLM01:2025 Prompt Injection
- LLM02:2025 Sensitive Information Disclosure
- LLM03:2025 Supply Chain
- LLM04:2025 Data and Model Poisoning
- LLM05:2025 Improper Output Handling
- LLM06:2025 Excessive Agency
- LLM07:2025 System Prompt Leakage
- LLM08:2025 Vector and Embedding Weaknesses
- LLM09:2025 Misinformation
- LLM10:2025 Unbounded Consumption

Do not use any other OWASP categories.`;

  return prompt;
}

// Function to fetch repository content from GitHub
async function fetchRepositoryContent(repositoryUrl) {
  try {
    // Extract owner and repo from the URL
    const urlMatch = repositoryUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    
    if (!urlMatch) {
      return { error: "Invalid GitHub repository URL format" };
    }
    
    const [, owner, repo] = urlMatch;
    const branch = 'main'; // Default to main branch

    console.log(`Fetching repository content for ${owner}/${repo}`);
    
    // First, get the repository tree recursively
    const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
    console.log(`Fetching tree from: ${treeUrl}`);
    
    const treeResponse = await fetch(treeUrl);
    
    if (!treeResponse.ok) {
      console.error(`GitHub API error: ${treeResponse.status}`);
      if (treeResponse.status === 404) {
        // Try with 'master' branch if 'main' not found
        const masterTreeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`;
        console.log(`Trying master branch: ${masterTreeUrl}`);
        
        const masterTreeResponse = await fetch(masterTreeUrl);
        
        if (!masterTreeResponse.ok) {
          return { error: `Could not find repository tree on main or master branch: ${masterTreeResponse.status}` };
        }
        
        const masterTree = await masterTreeResponse.json();
        return await processRepositoryTree(owner, repo, 'master', masterTree);
      }
      
      return { error: `GitHub API error: ${treeResponse.status}` };
    }
    
    const tree = await treeResponse.json();
    return await processRepositoryTree(owner, repo, branch, tree);
    
  } catch (error) {
    console.error('Error fetching repository content:', error);
    return { error: `Error fetching repository content: ${error.message}` };
  }
}

// Process the repository tree and fetch important files
async function processRepositoryTree(owner, repo, branch, tree) {
  if (!tree.tree) {
    return { error: "Invalid repository tree structure" };
  }

  // Filter for actual files (not directories)
  const fileNodes = tree.tree.filter(node => node.type === 'blob');
  
  console.log(`Found ${fileNodes.length} files in repository`);
  
  // Focus on key file types
  const importantExtensions = [
    '.py', '.js', '.ts', '.jsx', '.tsx', 
    '.java', '.rb', '.go', '.rs', '.php',
    '.md', '.ipynb'
  ];
  
  // Always include these files regardless of extension
  const importantFileNames = [
    'requirements.txt', 'package.json', 'Pipfile', 'Pipfile.lock', 
    'Gemfile', 'Gemfile.lock', 'go.mod', 'Cargo.toml', 'composer.json'
  ];
  
  // Filter for important files to analyze
  const importantFiles = fileNodes.filter(node => {
    const fileName = node.path.split('/').pop();
    
    // Always include important metadata files
    if (importantFileNames.some(name => fileName.toLowerCase() === name.toLowerCase())) {
      return true;
    }
    
    // Include files with important extensions
    const extension = '.' + fileName.split('.').pop();
    return importantExtensions.includes(extension);
  });
  
  console.log(`Identified ${importantFiles.length} important files for analysis`);
  
  // Sort by file path to help with context during analysis
  importantFiles.sort((a, b) => a.path.localeCompare(b.path));
  
  // For each file, fetch the content
  const files = [];
  
  const maxFilesToFetch = Math.min(importantFiles.length, 100); // Limit to prevent abuse
  const filePromises = [];
  
  for (let i = 0; i < maxFilesToFetch; i++) {
    const file = importantFiles[i];
    filePromises.push(fetchFileContent(owner, repo, branch, file.path));
  }
  
  const fetchedFiles = await Promise.all(filePromises);
  files.push(...fetchedFiles.filter(Boolean)); // Filter out any null results
  
  return {
    repositoryName: `${owner}/${repo}`,
    files: files
  };
}

// Fetch a single file's content
async function fetchFileContent(owner, repo, branch, path) {
  try {
    // Use the raw GitHub URL to get the file content
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
    console.log(`Fetching file: ${rawUrl}`);
    
    const response = await fetch(rawUrl);
    
    if (!response.ok) {
      console.error(`Error fetching file ${path}: ${response.status}`);
      return null;
    }
    
    const content = await response.text();
    
    return {
      path: path,
      content: content,
      extension: '.' + path.split('.').pop()
    };
  } catch (error) {
    console.error(`Error fetching file ${path}:`, error);
    return null;
  }
}

// Check for potential hardcoded system prompts
function isLikelySystemPrompt(line: string, fileContext: { path: string, content: string }): boolean {
  const lowerLine = line.toLowerCase();
  
  // Skip if line is a comment
  if (lowerLine.trim().startsWith('//') || lowerLine.trim().startsWith('/*') || lowerLine.trim().startsWith('*')) {
    return false;
  }

  // Skip if referencing environment variables or configs
  if (lowerLine.includes('process.env') || 
      lowerLine.includes('os.environ') || 
      lowerLine.includes('config.') ||
      lowerLine.includes('getenv')) {
    return false;
  }

  // Look for actual prompt assignment patterns
  const promptPatterns = [
    // OpenAI style system messages
    /(?:const|let|var)\s+\w+\s*=\s*[{[]\s*{\s*role\s*:\s*['"]system['"]\s*,\s*content\s*:/i,
    
    // Direct system prompt assignments
    /(?:const|let|var)\s+\w+\s*=\s*['"`]<\|system\|>/i,
    
    // Anthropic style system prompts
    /(?:const|let|var)\s+\w+\s*=\s*['"`]Human:/i,
    
    // Common template literal patterns
    /systemPrompt\s*=\s*`[^`]{10,}`/,
    
    // JSON-style prompt templates
    /"system_prompt":\s*"[^"]{10,}"/
  ];

  // Check if line matches any prompt pattern
  const hasPromptPattern = promptPatterns.some(pattern => pattern.test(line));
  
  if (!hasPromptPattern) {
    return false;
  }

  // Additional validation - check if line contains actual content
  const hasSubstantialContent = line.length > 50; // Arbitrary minimum length
  
  // Check if in test file
  const isTestFile = fileContext.path.toLowerCase().includes('test') || 
                     fileContext.path.toLowerCase().includes('spec');

  return hasSubstantialContent && !isTestFile;
}

// Simple scope detection
function detectScope(lines: string[], currentLine: number): string | undefined {
  // Look up for function/class definition
  for (let i = currentLine; i >= 0; i--) {
    const line = lines[i];
    if (!line) continue;  // Skip undefined lines
    const trimmedLine = line.trim();

    if (trimmedLine.match(/^(function|class|const|let|var)\s+\w+/)) {
      return trimmedLine;
    }
  }
  return undefined;
}

// Add debug logging for file scanning
function scanRepositoryFiles(repositoryContent: RepositoryContent) {
  const scannedFiles = new Set<string>();
  const skippedFiles = new Set<string>();

  for (const file of repositoryContent.files) {
    const filePath = file.path.toLowerCase();
    
    // Log all files found
    console.log(`Checking file: ${file.path}`);

    // Skip binary or extremely large files, but log them
    if (!file.content) {
      console.log(`Skipping empty file: ${file.path}`);
      skippedFiles.add(file.path);
      continue;
    }

    if (file.content.length > 100000) {
      console.log(`Skipping large file: ${file.path} (${file.content.length} bytes)`);
      skippedFiles.add(file.path);
      continue;
    }

    // Check file extensions case-insensitively
    const ext = filePath.substring(filePath.lastIndexOf('.'));
    const isCodeFile = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb']
      .includes(ext);

    if (!isCodeFile) {
      console.log(`Skipping non-code file: ${file.path}`);
      skippedFiles.add(file.path);
      continue;
    }

    scannedFiles.add(file.path);
    console.log(`Scanning file: ${file.path}`);
  }

  return {
    scanned: Array.from(scannedFiles),
    skipped: Array.from(skippedFiles)
  };
}
