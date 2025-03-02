import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.4.0"
import { Configuration, OpenAIApi } from "https://esm.sh/openai@3.3.0"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Core types
type RepositoryFile = {
  path: string;
  content: string;
  extension: string;
}

type RepositoryContent = {
  repositoryName: string;
  files: RepositoryFile[];
}

type CodeLocation = {
  file: string;
  line: number;
  snippet: string;
  context: {
    before: string[];
    after: string[];
    scope?: string;
  }
}

type AIComponent = {
  name: string;
  type: string;
  confidence: number;
  detectionMethod: 'import' | 'usage' | 'package' | 'configuration';
  locations: CodeLocation[];
}

// OWASP LLM Top 10 2025 Categories
export const OWASP_LLM_CATEGORIES = {
  PROMPT_INJECTION: {
    id: "LLM01:2025",
    name: "Prompt Injection",
    description: "Occurs when user inputs alter the LLM's behavior or output in unintended ways."
  },
  SENSITIVE_INFORMATION_DISCLOSURE: {
    id: "LLM02:2025",
    name: "Sensitive Information Disclosure",
    description: "Risks of exposing sensitive or personal information through LLM interactions."
  },
  SUPPLY_CHAIN: {
    id: "LLM03:2025",
    name: "Supply Chain",
    description: "Vulnerabilities in the LLM supply chain affecting the integrity of training data, models, and deployment."
  },
  DATA_AND_MODEL_POISONING: {
    id: "LLM04:2025",
    name: "Data and Model Poisoning",
    description: "Manipulation of training data to introduce vulnerabilities, backdoors, or biases."
  },
  IMPROPER_OUTPUT_HANDLING: {
    id: "LLM05:2025",
    name: "Improper Output Handling",
    description: "Insufficient validation or sanitization of LLM outputs leading to security risks."
  },
  EXCESSIVE_AGENCY: {
    id: "LLM06:2025",
    name: "Excessive Agency",
    description: "Risks where LLMs perform actions beyond intended limits or authority."
  },
  SYSTEM_PROMPT_LEAKAGE: {
    id: "LLM07:2025",
    name: "System Prompt Leakage",
    description: "Exposure of system prompts revealing internal logic or configurations."
  },
  VECTOR_AND_EMBEDDING_WEAKNESSES: {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Weaknesses in how vectors and embeddings are generated, stored, or retrieved."
  },
  MISINFORMATION: {
    id: "LLM09:2025",
    name: "Misinformation",
    description: "Generation of false or misleading information presented as factual."
  },
  UNBOUNDED_CONSUMPTION: {
    id: "LLM10:2025",
    name: "Unbounded Consumption",
    description: "Risks where LLMs consume resources without proper limits, potentially leading to denial of service."
  },
  INSECURE_OUTPUT_HANDLING: {
    id: "LLM05:2025",
    name: "Insecure Output Handling",
    description: "Output handling that exposes sensitive information or leads to security risks."
  }
} as const;

// Helper type for severity levels
type Severity = 'high' | 'medium' | 'low';

// Update SecurityRisk type to use OWASP categories
type SecurityRisk = {
  risk: string;
  severity: Severity;
  description: string;
  owaspCategory: typeof OWASP_LLM_CATEGORIES[keyof typeof OWASP_LLM_CATEGORIES];
  relatedComponents: string[];
  evidence: CodeLocation[];
  confidence: number;
};

type AnalysisResult = {
  repositoryName: string;
  timestamp: string;
  aiComponents: AIComponent[];
  securityRisks: SecurityRisk[];
  callGraph: {
    nodes: string[];
    edges: Array<{
      from: string;
      to: string;
      type: string;
    }>;
  };
  summary: {
    totalAIUsage: number;
    risksByLevel: {
      high: number;
      medium: number;
      low: number;
    };
    topRisks: string[];
  };
}

// Detection patterns
const AI_PATTERNS = {
  imports: {
    langchain: /from\s+langchain|import.*langchain|require\(['"]langchain/i,
    openai: /from\s+openai|import.*openai|require\(['"]openai/i,
    anthropic: /from\s+anthropic|import.*anthropic|require\(['"]anthropic/i,
    huggingface: /from\s+transformers|import.*transformers|require\(['"]transformers/i,
    vectordb: /(pinecone|weaviate|chromadb|qdrant)/i
  },
  models: {
    gpt: /gpt-[34]\.[45]|gpt-4|text-davinci/i,
    claude: /claude-[12]|claude-instant/i,
    llama: /llama-[127]b|llama2/i,
    mistral: /mistral-[127]b|mixtral/i
  },
  systemPrompts: {
    openai: /role:\s*['"]system['"],\s*content:/i,
    anthropic: /\bHuman:\s*.*?\bAssistant:/is,
    general: /system[_-]?prompt|instruction[_-]?template/i
  }
};

// Add after AI_PATTERNS

const PACKAGE_PATTERNS = {
  python: {
    files: ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py'],
    aiLibraries: {
      'openai': { type: 'LLM API' },
      'langchain': { type: 'LLM Framework' },
      'transformers': { type: 'ML Framework' },
      'sentence-transformers': { type: 'Embedding Generation' },
      'pinecone-client': { type: 'Vector Database' },
      'chromadb': { type: 'Vector Database' },
      'llama-cpp-python': { type: 'LLM Framework' },
      'anthropic': { type: 'LLM API' },
      'cohere': { type: 'LLM API' }
    }
  },
  node: {
    files: ['package.json'],
    aiLibraries: {
      '@openai/openai-api': { type: 'LLM API' },
      'langchain': { type: 'LLM Framework' },
      '@huggingface/inference': { type: 'ML Framework' },
      '@pinecone-database/pinecone': { type: 'Vector Database' },
      'chromadb': { type: 'Vector Database' },
      '@anthropic-ai/sdk': { type: 'LLM API' }
    }
  }
};

function analyzePackageFiles(files: RepositoryFile[]): AIComponent[] {
  const components: AIComponent[] = [];
  
  for (const file of files) {
    // Python requirements.txt
    if (file.path.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      for (const line of lines) {
        const pkg = line.split('==')[0].split('>=')[0].trim();
        if (PACKAGE_PATTERNS.python.aiLibraries[pkg]) {
          components.push({
            name: pkg,
            type: PACKAGE_PATTERNS.python.aiLibraries[pkg].type,
            confidence: 0.95,
            detectionMethod: 'package',
            locations: [{
              file: file.path,
              line: lines.indexOf(line) + 1,
              snippet: line,
              context: {
                before: lines.slice(Math.max(0, lines.indexOf(line) - 2), lines.indexOf(line)),
                after: lines.slice(lines.indexOf(line) + 1, lines.indexOf(line) + 3),
                scope: 'Global'
              }
            }]
          });
        }
      }
    }
    
    // package.json
    if (file.path.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          if (PACKAGE_PATTERNS.node.aiLibraries[name]) {
            components.push({
              name,
              type: PACKAGE_PATTERNS.node.aiLibraries[name].type,
              confidence: 0.95,
              detectionMethod: 'package',
              locations: [{
                file: file.path,
                line: 1, // We'd need a JSON parser to get exact line numbers
                snippet: `"${name}": "${version}"`,
                context: {
                  before: [],
                  after: [],
                  scope: 'dependencies'
                }
              }]
            });
          }
        }
      } catch (e) {
        console.error('Error parsing package.json:', e);
      }
    }
  }
  
  return components;
}

// Simple in-memory cache (will reset on function restart)
const analysisCache = new Map<string, AnalysisResult>();

// Main handler
serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { repositoryUrl } = await req.json()
    
    // Check cache first
    const cacheKey = repositoryUrl;
    const cached = analysisCache.get(cacheKey);
    if (cached) {
      return new Response(JSON.stringify(cached), 
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Fetch and analyze repository
    const repositoryContent = await fetchRepositoryContent(repositoryUrl);
    const result = await analyzeRepository(repositoryContent);

    // Store in repository_analyses table
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? ''
    );

    await supabase
      .from('repository_analyses')
      .insert({
        repository_url: repositoryUrl,
        analysis_result: result
      });

    // Cache the result
    analysisCache.set(cacheKey, result);

    return new Response(
      JSON.stringify(result),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 400
    });
  }
})

// Type guard
function isValidRepositoryContent(content: any): content is RepositoryContent {
  return content && 
         typeof content.repositoryName === 'string' &&
         Array.isArray(content.files) &&
         content.files.every(file => 
           typeof file.path === 'string' &&
           typeof file.content === 'string' &&
           typeof file.extension === 'string'
         );
}

// Our graph is simple enough to manage without a library
type CallGraph = {
  nodes: string[];
  edges: Array<{
    from: string;
    to: string;
    type: string;
  }>;
};

// Main analysis function (to be implemented next)
async function analyzeRepository(content: RepositoryContent): Promise<AnalysisResult> {
  try {
    console.log('Starting repository analysis...');
    
    // Step 1: Detect AI components
    console.log('Detecting AI components...');
    const aiComponents = detectAIComponents(content.files);
    console.log('AI components found:', aiComponents);
    
    // Step 2: Initialize tracking
    const detectedLibraries = new Set(aiComponents.map(c => c.name));
    console.log('Detected libraries:', Array.from(detectedLibraries));
    
    const callGraph: CallGraph = {
      nodes: [],
      edges: []
    };

    // Step 3: Scan for AI components
    console.log('Scanning for AI components...');
    const detectedImports = new Map<string, Set<string>>();

    for (const file of content.files) {
      console.log(`Analyzing file: ${file.path}`);
      // Skip non-code files
      if (!['.py', '.js', '.ts', '.jsx', '.tsx'].includes(file.extension)) {
        continue;
      }

      const lines = file.content.split('\n');
      
      // Track imports and build graph
      lines.forEach((line, lineIndex) => {
        // Check for imports
        for (const [library, pattern] of Object.entries(AI_PATTERNS.imports)) {
          if (pattern.test(line)) {
            console.log(`Found AI library: ${library} in file: ${file.path}`);
            // Add to graph
            if (!callGraph.nodes.includes(file.path)) {
              callGraph.nodes.push(file.path);
            }
            
            // Record the import
            if (!detectedImports.has(file.path)) {
              detectedImports.set(file.path, new Set());
            }
            detectedImports.get(file.path)?.add(library);

            // Add component with high confidence due to direct import
            aiComponents.push({
              name: library,
              type: 'Library',
              confidence: 0.9,
              detectionMethod: 'import',
              locations: [{
                file: file.path,
                line: lineIndex + 1,
                snippet: line.trim(),
                context: {
                  before: lines.slice(Math.max(0, lineIndex - 2), lineIndex),
                  after: lines.slice(lineIndex + 1, lineIndex + 3),
                  scope: detectScope(lines, lineIndex)
                }
              }]
            });
          }
        }
      });
    }

    // Step 4: Security risk analysis
    console.log('Analyzing security risks...');
    const securityRisks = detectSecurityRisks(content.files, aiComponents);

    console.log('Analysis complete. Found:');
    console.log(`- ${aiComponents.length} AI components`);
    console.log(`- ${securityRisks.length} security risks`);
    console.log(`- ${callGraph.nodes.length} files in call graph`);

    return {
      repositoryName: content.repositoryName,
      timestamp: new Date().toISOString(),
      aiComponents,
      securityRisks,
      callGraph,
      summary: {
        totalAIUsage: aiComponents.length,
        risksByLevel: {
          high: securityRisks.filter(r => r.severity === 'high').length,
          medium: securityRisks.filter(r => r.severity === 'medium').length,
          low: securityRisks.filter(r => r.severity === 'low').length
        },
        topRisks: securityRisks
          .sort((a, b) => b.confidence - a.confidence)
          .slice(0, 3)
          .map(r => r.risk)
      }
    };
  } catch (error) {
    console.error('Error in analyzeRepository:', error);
    throw error; // Let the outer try-catch handle it
  }
}

// Helper function to detect code scope
function detectScope(lines: string[], currentLineIndex: number): string {
  // Look backward to find function or class definition
  for (let i = currentLineIndex; i >= 0; i--) {
    if (/\b(function|def|class)\s+(\w+)/.test(lines[i])) {
      const match = lines[i].match(/\b(function|def|class)\s+(\w+)/);
      return match ? match[2] : 'Function';
    }
  }
  return 'Global';
}

// Helper to check if a file has a vector DB component
function hasVectorDBComponent(components: AIComponent[], filePath: string): boolean {
  return components.some(component => 
    component.type === 'Vector Database' && 
    component.locations.some(loc => loc.file === filePath)
  );
}

//  GitHub API utilities 
async function fetchRepositoryContent(url: string): Promise<RepositoryContent> {
  // Parse GitHub URL
  const match = url.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) {
    throw new Error('Invalid GitHub repository URL');
  }

  const [_, owner, repo] = match;
  const branch = 'main'; // Could make this configurable

  try {
    // Use the public API (no auth required)
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
    );

    console.log('GitHub API Response:', {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
    });

    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('GitHub API rate limit exceeded. Please try again later.');
      }
      throw new Error(`GitHub API error: ${response.statusText}`);
    }

    const data = await response.json();
    
    // Add logging for file filtering
    const relevantFiles = data.tree.filter(item => {
      const isRelevant = item.type === 'blob' && (
        item.path.endsWith('.py') ||
        item.path.endsWith('.js') ||
        item.path.endsWith('.ts') ||
        item.path.endsWith('.tsx') ||
        item.path.endsWith('.jsx') ||
        item.path.endsWith('requirements.txt') ||
        item.path.endsWith('package.json')
      );
      console.log(`File ${item.path}: ${isRelevant ? 'relevant' : 'skipped'}`);
      return isRelevant;
    });

    // Fetch raw content directly (no auth needed)
    const files = await Promise.all(
      relevantFiles.map(async file => {
        try {
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
          const contentResponse = await fetch(rawUrl);

          if (!contentResponse.ok) {
            console.error(`Failed to fetch ${file.path}: ${contentResponse.statusText}`);
            return null;
          }

          const content = await contentResponse.text();
          return {
            path: file.path,
            content,
            extension: '.' + file.path.split('.').pop()
          };
        } catch (error) {
          console.error(`Error fetching ${file.path}:`, error);
          return null;
        }
      })
    );

    return {
      repositoryName: `${owner}/${repo}`,
      files: files.filter((f): f is RepositoryFile => f !== null)
    };
  } catch (error) {
    throw new Error(`Failed to fetch repository: ${error.message}`);
  }
}

// Example JSON Output Format (moved to bottom)
/*
{
  "repositoryName": "example/ai-project",
  "timestamp": "2024-03-19T15:30:45.123Z",
  "aiComponents": [
    {
      "name": "langchain",
      "type": "LLM Framework",
      "confidence": 0.95,
      "detectionMethod": "package",
      "locations": [
        {
          "file": "requirements.txt",
          "line": 1,
          "snippet": "langchain==0.1.0",
          "context": {
            "before": [],
            "after": ["openai>=1.0.0"],
            "scope": "Global"
          }
        }
      ]
    },
    {
      "name": "openai",
      "type": "LLM API",
      "confidence": 0.9,
      "detectionMethod": "import",
      "locations": [
        {
          "file": "src/chat.py",
          "line": 45,
          "snippet": "from openai import ChatCompletion",
          "context": {
            "before": ["import os"],
            "after": ["from dotenv import load_dotenv"],
            "scope": "Global"
          }
        }
      ]
    }
  ],
  "securityRisks": [
    {
      "risk": "Direct Model Usage",
      "severity": "high",
      "description": "Direct usage of GPT-4 model detected",
      "owaspCategory": {
        "id": "LLM01:2025",
        "name": "Prompt Injection",
        "description": "Occurs when user inputs alter the LLM's behavior or output in unintended ways."
      },
      "relatedComponents": ["openai"],
      "evidence": [
        {
          "file": "src/chat.py",
          "line": 46,
          "snippet": "response = ChatCompletion.create(model='gpt-4')",
          "context": {
            "before": ["def generate_response(prompt):"],
            "after": ["    return response.choices[0].message"],
            "scope": "generate_response"
          }
        }
      ],
      "confidence": 0.95
    }
  ],
  "callGraph": {
    "nodes": ["src/main.py", "src/chat.py", "src/prompts.py"],
    "edges": [
      {
        "from": "src/main.py",
        "to": "src/chat.py",
        "type": "import"
      },
      {
        "from": "src/chat.py",
        "to": "src/prompts.py",
        "type": "import"
      }
    ]
  },
  "summary": {
    "totalAIUsage": 2,
    "risksByLevel": {
      "high": 1,
      "medium": 2,
      "low": 0
    },
    "topRisks": [
      "Direct Model Usage",
      "System Prompt Exposure",
      "Vector Database Access"
    ]
  }
}
*/ 

function categorizeRisk(context: {
  hasRag: boolean;
  hasEmbeddings: boolean;
  hasSystemPrompt: boolean;
  hasVectorDB: boolean;
  directModelUsage: boolean;
  modelType: string;
}): typeof OWASP_LLM_CATEGORIES[keyof typeof OWASP_LLM_CATEGORIES] {

  // LLM02: Sensitive Information Disclosure
  if (context.hasRag && context.hasVectorDB) {
    return OWASP_LLM_CATEGORIES.SENSITIVE_INFORMATION_DISCLOSURE;
  }

  // LLM04: Data and Model Poisoning
  if (context.hasEmbeddings) {
    return OWASP_LLM_CATEGORIES.DATA_AND_MODEL_POISONING;
  }

  // LLM07: System Prompt Leakage
  if (context.hasSystemPrompt) {
    return OWASP_LLM_CATEGORIES.SYSTEM_PROMPT_LEAKAGE;
  }

  // LLM08: Vector/Embedding Weaknesses
  if (context.hasVectorDB) {
    return OWASP_LLM_CATEGORIES.VECTOR_AND_EMBEDDING_WEAKNESSES;
  }

  // LLM01: Prompt Injection (default for direct model usage)
  if (context.directModelUsage) {
    return OWASP_LLM_CATEGORIES.PROMPT_INJECTION;
  }

  // Default fallback
  return OWASP_LLM_CATEGORIES.PROMPT_INJECTION;
} 

// Add to the types section
type RiskContext = {
  code: string;
  imports: string[];
  modelUsage: string[];
  systemPrompts: string[];
  vectorStores: string[];
  embeddings: string[];
  packageDependencies: string[];
};

async function analyzeSecurityRisk(risk: SecurityRisk, context: RiskContext): Promise<typeof OWASP_LLM_CATEGORIES[keyof typeof OWASP_LLM_CATEGORIES]> {
  const prompt = `
As a security expert, analyze this AI security risk and categorize it according to the OWASP LLM Top 10 2025.
Consider all context carefully.

Risk: ${risk.risk}
Description: ${risk.description}
Severity: ${risk.severity}

Context:
- Imports: ${context.imports.join(', ')}
- Model Usage: ${context.modelUsage.join(', ')}
- System Prompts Found: ${context.systemPrompts.join(', ')}
- Vector Stores: ${context.vectorStores.join(', ')}
- Embeddings: ${context.embeddings.join(', ')}
- Dependencies: ${context.packageDependencies.join(', ')}

Code Evidence:
${risk.evidence.map(e => `${e.file}:${e.line} - ${e.snippet}`).join('\n')}

OWASP LLM Categories:
${Object.entries(OWASP_LLM_CATEGORIES).map(([key, cat]) => 
  `${cat.id}: ${cat.name} - ${cat.description}`
).join('\n')}

Return only the category ID that best matches this risk.
`;

  // Call GPT-4 for analysis
  const category = await callGPT4(prompt);
  
  // Map the response back to our categories
  const matchedCategory = Object.values(OWASP_LLM_CATEGORIES)
    .find(cat => cat.id === category.trim());

  return matchedCategory || OWASP_LLM_CATEGORIES.PROMPT_INJECTION;
} 

async function callGPT4(prompt: string): Promise<string> {
  const openaiApiKey = Deno.env.get('OPENAI_API_KEY');
  if (!openaiApiKey) {
    throw new Error('OpenAI API key not configured');
  }

  const configuration = new Configuration({ apiKey: openaiApiKey });
  const openai = new OpenAIApi(configuration);

  try {
    const response = await openai.createChatCompletion({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: "You are a security expert specializing in LLM applications. Analyze risks and categorize them according to OWASP LLM Top 10 2025. Respond only with the category ID."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.1, // Low temperature for consistent categorization
      max_tokens: 10   // We only need the category ID
    });

    const category = response.data.choices[0]?.message?.content?.trim() || "LLM01:2025";
    console.log('GPT-4 categorized risk as:', category);
    return category;
  } catch (error) {
    console.error('Error calling GPT-4:', error);
    // Fallback to Prompt Injection category if GPT-4 call fails
    return "LLM01:2025";
  }
} 

// Step 2: Completely redesign risk detection
function detectSecurityRisks(files: RepositoryFile[], components: AIComponent[]): SecurityRisk[] {
  // Create a map of risk types to avoid duplication
  const riskMap = new Map<string, SecurityRisk>();
  
  // Check if we have RAG components (vector databases + LLMs)
  const hasVectorDB = components.some(c => c.type === 'Vector Database');
  const hasLLM = components.some(c => 
    c.type === 'LLM Provider' || 
    c.name.toLowerCase().includes('openai') || 
    c.name.toLowerCase().includes('anthropic')
  );
  
  // Initialize RAG-specific risks if we have both vector DBs and LLMs
  if (hasVectorDB && hasLLM) {
    // LLM08:2025 - Vector and Embedding Weaknesses
    riskMap.set("RAG Data Leakage", {
      risk: "RAG Data Leakage",
      severity: "medium" as Severity,
      description: "RAG implementation may leak sensitive information through vector retrieval",
      owaspCategory: OWASP_LLM_CATEGORIES.VECTOR_AND_EMBEDDING_WEAKNESSES,
      relatedComponents: [],
      evidence: [],
      confidence: 0.85
    });
    
    // LLM01:2025 - Prompt Injection
    riskMap.set("RAG Prompt Injection", {
      risk: "RAG Prompt Injection",
      severity: "high" as Severity,
      description: "User input is used in RAG queries without proper sanitization",
      owaspCategory: OWASP_LLM_CATEGORIES.PROMPT_INJECTION,
      relatedComponents: [],
      evidence: [],
      confidence: 0.9
    });
  }
  
  // LLM07:2025 - System Prompt Leakage
  riskMap.set("System Prompt Exposure", {
    risk: "System Prompt Exposure",
    severity: "medium" as Severity,
    description: "System prompts hardcoded in application code",
    owaspCategory: OWASP_LLM_CATEGORIES.SYSTEM_PROMPT_LEAKAGE,
    relatedComponents: [],
    evidence: [],
    confidence: 0.9
  });
  
  // LLM03:2025 - Supply Chain
  riskMap.set("Hardcoded API Keys", {
    risk: "Hardcoded API Keys",
    severity: "high" as Severity,
    description: "API keys or credentials found directly in code",
    owaspCategory: OWASP_LLM_CATEGORIES.SUPPLY_CHAIN,
    relatedComponents: [],
    evidence: [],
    confidence: 0.95
  });
  
  // Scan each file for risks
  for (const file of files) {
    const lines = file.content.split('\n');
    
    // Check for API keys
    const apiKeyPattern = /(api[-_]?key|apikey|api-key|OPENAI_API_KEY|PINECONEAPI|OPENAIKEY)[\s]*=[\s]*["']?[A-Za-z0-9\-_]+["']?/i;
    lines.forEach((line, index) => {
      if (apiKeyPattern.test(line)) {
        const risk = riskMap.get("Hardcoded API Keys")!;
        risk.evidence.push({
          file: file.path,
          line: index + 1,
          snippet: line.trim(),
          context: {
            before: lines.slice(Math.max(0, index - 2), index),
            after: lines.slice(index + 1, Math.min(lines.length, index + 3)),
            scope: detectScope(lines, index)
          }
        });
      }
    });
    
    // Check for RAG prompt injection vulnerabilities
    if (hasVectorDB && hasLLM) {
      // Look for query operations that might use user input
      const queryLines = lines
        .map((line, idx) => ({ line, idx }))
        .filter(({ line }) => 
          /\.query\s*\(/.test(line) && 
          /user|input|prompt|message|text/.test(line) &&
          !/sanitize|validate|clean/.test(line.toLowerCase())
        );
        
      if (queryLines.length > 0) {
        const risk = riskMap.get("RAG Prompt Injection")!;
        queryLines.forEach(({ line, idx }) => {
          risk.evidence.push({
            file: file.path,
            line: idx + 1,
            snippet: line.trim(),
            context: {
              before: lines.slice(Math.max(0, idx - 2), idx),
              after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
              scope: detectScope(lines, idx)
            }
          });
        });
      }
      
      // Check for potential data leakage in RAG
      if (file.path.includes('pinecone') || file.content.includes('vector') || file.content.includes('embed')) {
        const dataLeakageLines = lines
          .map((line, idx) => ({ line, idx }))
          .filter(({ line }) => 
            /upsert|index|store/.test(line) && 
            !/filter|sanitize|redact/.test(line.toLowerCase())
          );
          
        if (dataLeakageLines.length > 0) {
          const risk = riskMap.get("RAG Data Leakage")!;
          dataLeakageLines.forEach(({ line, idx }) => {
            risk.evidence.push({
              file: file.path,
              line: idx + 1,
              snippet: line.trim(),
              context: {
                before: lines.slice(Math.max(0, idx - 2), idx),
                after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
                scope: detectScope(lines, idx)
              }
            });
          });
        }
      }
    }
    
    // Check for system prompts
    const systemPromptPattern = /(system_prompt|system prompt|systemPrompt|SystemMessage)[\s]*=[\s]*["'`]|content=["'`]/i;
    lines.forEach((line, index) => {
      if (systemPromptPattern.test(line)) {
        const risk = riskMap.get("System Prompt Exposure")!;
        risk.evidence.push({
          file: file.path,
          line: index + 1,
          snippet: line.trim(),
          context: {
            before: lines.slice(Math.max(0, index - 2), index),
            after: lines.slice(index + 1, Math.min(lines.length, index + 3)),
            scope: detectScope(lines, index)
          }
        });
      }
    });
  }
  
  // Filter out risks with no evidence
  return Array.from(riskMap.values()).filter(risk => risk.evidence.length > 0);
} 

// Step 1: Completely redesign how we detect AI components
function detectAIComponents(files: RepositoryFile[]): AIComponent[] {
  // Track unique components by name to avoid duplication
  const componentMap = new Map<string, AIComponent>();
  
  // Track which files have been processed for vector DB references
  // to avoid duplicate detections
  const processedVectorDBFiles = new Set<string>();
  
  for (const file of files) {
    const lines = file.content.split('\n');
    
    // Check for imports - use regex to extract the actual package name
    const importMatches = [...file.content.matchAll(/import\s+(?:{\s*[^}]*\s*}|[^;]+)\s+from\s+['"]([^'"]+)['"]/g)];
    
    for (const match of importMatches) {
      const packageName = match[1];
      let componentType = '';
      
      // Categorize the import
      if (/langchain|llm-chain/.test(packageName)) {
        componentType = 'LLM Framework';
      } else if (/openai|anthropic|cohere|huggingface|google-generative/.test(packageName)) {
        componentType = 'LLM Provider';
      } else if (/pinecone|chroma|qdrant|weaviate|milvus/.test(packageName)) {
        componentType = 'Vector Database';
        // Mark this file as processed for vector DB
        processedVectorDBFiles.add(file.path);
      } else if (/sentence-transformers|embedding/.test(packageName)) {
        componentType = 'Embedding Model';
      } else {
        // Skip non-AI packages
        continue;
      }
      
      // Get the line number and context
      const lineIndex = lines.findIndex(line => line.includes(packageName));
      
      // Create or update component
      const componentName = packageName.split('/').pop() || packageName;
      if (!componentMap.has(componentName)) {
        componentMap.set(componentName, {
          name: componentName,
          type: componentType,
          confidence: 0.95,
          detectionMethod: 'import',
          locations: []
        });
      }
      
      // Add this location
      componentMap.get(componentName)!.locations.push({
        file: file.path,
        line: lineIndex + 1,
        snippet: lines[lineIndex],
        context: {
          before: lines.slice(Math.max(0, lineIndex - 2), lineIndex),
          after: lines.slice(lineIndex + 1, Math.min(lines.length, lineIndex + 3)),
          scope: 'Global'
        }
      });
    }
    
    // Also check for actual usage patterns (not just imports)
    // This would detect instantiations like "new PineconeClient()" or "ChatOpenAI()"
    const usagePatterns = [
      { pattern: /new\s+Pinecone\(|Pinecone\(/, type: 'Vector Database', name: 'pinecone' },
      { pattern: /ChatOpenAI\(/, type: 'LLM Provider', name: 'openai' },
      { pattern: /ChatAnthropic\(/, type: 'LLM Provider', name: 'anthropic' },
      { pattern: /ChatGoogleGenerativeAI\(/, type: 'LLM Provider', name: 'google-ai' }
    ];
    
    for (const { pattern, type, name } of usagePatterns) {
      if (pattern.test(file.content)) {
        // Find the line
        const lineIndex = lines.findIndex(line => pattern.test(line));
        if (lineIndex >= 0) {
          if (!componentMap.has(name)) {
            componentMap.set(name, {
              name,
              type,
              confidence: 0.9,
              detectionMethod: 'usage',
              locations: []
            });
          }
          
          // For vector databases, skip if we've already processed this file
          if (type === 'Vector Database' && processedVectorDBFiles.has(file.path)) {
            continue;
          }
          
          // Mark this file as processed for vector DB if it's a vector DB component
          if (type === 'Vector Database') {
            processedVectorDBFiles.add(file.path);
          }
          
          componentMap.get(name)!.locations.push({
            file: file.path,
            line: lineIndex + 1,
            snippet: lines[lineIndex],
            context: {
              before: lines.slice(Math.max(0, lineIndex - 2), lineIndex),
              after: lines.slice(lineIndex + 1, Math.min(lines.length, lineIndex + 3)),
              scope: detectScope(lines, lineIndex)
            }
          });
        }
      }
    }
    
    // Skip the vectordb library detection for files we've already processed
    if (processedVectorDBFiles.has(file.path)) {
      continue;
    }
    
    // Don't add generic "vectordb" components based on mentions in comments or variable names
  }
  
  return Array.from(componentMap.values());
} 
