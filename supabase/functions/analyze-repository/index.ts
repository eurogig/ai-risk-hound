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
    const result = await analyzeRepository(repositoryContent.files);

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
async function analyzeRepository(files: RepositoryFile[]): Promise<AnalysisResult> {
  try {
    console.log('Starting repository analysis...');
    
    // Direct implementation (no need for analyzeRepositoryComponents)
    const dependencies = extractDependencies(files);
    const imports = trackImports(files, dependencies);
    const components = findComponentUsage(files, imports);
    const risks = identifyRisks(files, components, imports);
    
    // Build the call graph
    const callGraph = buildCallGraph(files, components);
    
    // Calculate summary statistics
    const summary = {
      totalAIUsage: components.length,
      risksByLevel: {
        high: risks.filter(r => r.severity === 'high').length,
        medium: risks.filter(r => r.severity === 'medium').length,
        low: risks.filter(r => r.severity === 'low').length
      },
      topRisks: risks.slice(0, 3).map(r => r.risk)
    };
    
    // Get repository name from the first file path or use a default
    const repositoryName = files.length > 0 ? 
      files[0].path.split('/')[0] || 'unknown-repository' : 
      'unknown-repository';
    
    return {
      repositoryName,
      timestamp: new Date().toISOString(),
      aiComponents: components,
      securityRisks: risks,
      callGraph,
      summary
    };
  } catch (error) {
    console.error('Error in repository analysis:', error);
    throw error;
  }
}

// Add the missing detectScope function
function detectScope(lines: string[], lineIndex: number): string {
  // Simple scope detection - look for function or class definitions above the current line
  for (let i = lineIndex; i >= 0; i--) {
    const line = lines[i];
    // Match function definitions in various languages
    if (/^\s*(function|def|class|const\s+\w+\s*=\s*\(|async\s+function)\s+(\w+)/.test(line)) {
      const match = line.match(/^\s*(function|def|class|const\s+\w+\s*=\s*\(|async\s+function)\s+(\w+)/);
      return match ? match[2] : "Unknown";
    }
  }
  return "Global";
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

function extractDependencies(files: RepositoryFile[]): Map<string, string[]> {
  const dependencyMap = new Map<string, string[]>();
  
  // Known mappings between package names and import names
  const packageToImportMap: Record<string, string[]> = {
    'pinecone-client': ['pinecone'],
    'langchain': ['langchain'],
    'openai': ['openai'],
    'anthropic': ['anthropic'],
    '@google/generative-ai': ['google-generative-ai', 'googleGenerativeAI'],
    // Add more mappings as needed
  };
  
  // Check package.json, requirements.txt, etc.
  for (const file of files) {
    if (file.path.endsWith('package.json')) {
      try {
        const packageJson = JSON.parse(file.content);
        const allDeps = {
          ...(packageJson.dependencies || {}),
          ...(packageJson.devDependencies || {})
        };
        
        for (const [pkg, version] of Object.entries(allDeps)) {
          if (packageToImportMap[pkg]) {
            dependencyMap.set(pkg, packageToImportMap[pkg]);
          }
        }
      } catch (e) {
        console.error('Error parsing package.json:', e);
      }
    }
    
    if (file.path.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      for (const line of lines) {
        // Extract package name from requirements.txt line
        const match = line.match(/^([a-zA-Z0-9_-]+)([><=~]|$)/);
        if (match && packageToImportMap[match[1]]) {
          dependencyMap.set(match[1], packageToImportMap[match[1]]);
        }
      }
    }
  }
  
  return dependencyMap;
}

function trackImports(files: RepositoryFile[], dependencies: Map<string, string[]>): Map<string, Set<string>> {
  // Map of file paths to sets of imported modules and their aliases
  const importMap = new Map<string, Set<string>>();
  
  // Flattened list of all possible import names to look for
  const allImportNames = Array.from(dependencies.values()).flat();
  
  for (const file of files) {
    const importSet = new Set<string>();
    
    // Different import patterns for different languages
    if (file.extension === '.py') {
      // Python imports
      const importRegexes = [
        /from\s+([a-zA-Z0-9_.]+)\s+import\s+([^#\n]+)/g,  // from X import Y
        /import\s+([^#\n]+)/g  // import X
      ];
      
      for (const regex of importRegexes) {
        const matches = [...file.content.matchAll(regex)];
        for (const match of matches) {
          const importPath = match[1];
          
          // Check if this import matches any of our target dependencies
          if (allImportNames.some(name => importPath.includes(name))) {
            importSet.add(importPath);
            
            // If it's a "from X import Y" pattern, also track the imported items
            if (match[2]) {
              const importedItems = match[2].split(',').map(item => item.trim().split(' as ')[0]);
              for (const item of importedItems) {
                importSet.add(item);
              }
            }
          }
        }
      }
    } else if (['.js', '.ts', '.jsx', '.tsx'].includes(file.extension)) {
      // JavaScript/TypeScript imports
      const importRegexes = [
        /import\s+(?:{\s*([^}]+)\s*}|([^;]+))\s+from\s+['"]([^'"]+)['"]/g,  // import { X } from 'Y' or import X from 'Y'
        /const\s+([a-zA-Z0-9_]+)\s+=\s+require\(['"]([^'"]+)['"]\)/g  // const X = require('Y')
      ];
      
      for (const regex of importRegexes) {
        const matches = [...file.content.matchAll(regex)];
        for (const match of matches) {
          const importPath = match[3] || match[2];
          
          // Check if this import matches any of our target dependencies
          if (allImportNames.some(name => importPath?.includes(name))) {
            importSet.add(importPath);
            
            // If it's a destructured import, also track the imported items
            if (match[1]) {
              const importedItems = match[1].split(',').map(item => item.trim().split(' as ')[0]);
              for (const item of importedItems) {
                importSet.add(item);
              }
            }
            
            // If it's a default import or require, track the variable name
            if (match[2] || match[1]) {
              importSet.add(match[2] || match[1]);
            }
          }
        }
      }
    }
    
    if (importSet.size > 0) {
      importMap.set(file.path, importSet);
    }
  }
  
  return importMap;
}

function findComponentUsage(files: RepositoryFile[], imports: Map<string, Set<string>>): AIComponent[] {
  const components: AIComponent[] = [];
  const componentMap = new Map<string, AIComponent>();
  
  // Component type classification
  const componentTypes: Record<string, string> = {
    'pinecone': 'Vector Database',
    'openai': 'LLM Provider',
    'anthropic': 'LLM Provider',
    'langchain': 'LLM Framework',
    // Add more as needed
  };
  
  for (const [filePath, importSet] of imports.entries()) {
    const file = files.find(f => f.path === filePath);
    if (!file) continue;
    
    const lines = file.content.split('\n');
    
    // Look for actual usage of imported modules
    for (const importName of importSet) {
      // Skip common words that might cause false positives
      if (['from', 'import', 'as'].includes(importName)) continue;
      
      // Determine component type
      let componentType = 'Library';
      for (const [pattern, type] of Object.entries(componentTypes)) {
        if (importName.toLowerCase().includes(pattern)) {
          componentType = type;
          break;
        }
      }
      
      // Look for instantiation or usage
      const usageLines = lines
        .map((line, idx) => ({ line, idx }))
        .filter(({ line }) => {
          // Match patterns like: new X(), X(), X.method(), const y = X
          const pattern = new RegExp(`(new\\s+${importName}|${importName}\\s*\\(|${importName}\\.[a-zA-Z]+|=\\s*${importName})`, 'i');
          return pattern.test(line);
        });
      
      if (usageLines.length > 0) {
        // Create or update component
        const componentName = importName;
        if (!componentMap.has(componentName)) {
          componentMap.set(componentName, {
            name: componentName,
            type: componentType,
            confidence: 0.95,
            detectionMethod: 'usage',
            locations: []
          });
        }
        
        // Add usage locations (limit to 3 most relevant)
        const component = componentMap.get(componentName)!;
        for (const { line, idx } of usageLines.slice(0, 3)) {
          component.locations.push({
            file: filePath,
            line: idx + 1,
            snippet: line.trim(),
            context: {
              before: lines.slice(Math.max(0, idx - 2), idx),
              after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
              scope: detectScope(lines, idx)
            }
          });
        }
      }
    }
  }
  
  return Array.from(componentMap.values());
}

function identifyRisks(files: RepositoryFile[], components: AIComponent[], imports: Map<string, Set<string>>): SecurityRisk[] {
  const risks: SecurityRisk[] = [];
  const riskMap = new Map<string, SecurityRisk>();
  
  // Check for vector database + LLM combination (RAG pattern)
  const vectorDBComponents = components.filter(c => c.type === 'Vector Database');
  const llmComponents = components.filter(c => c.type === 'LLM Provider');
  
  if (vectorDBComponents.length > 0 && llmComponents.length > 0) {
    // We have a RAG pattern - look for specific risks
    
    // 1. RAG Prompt Injection risk
    const promptInjectionRisk: SecurityRisk = {
      risk: "RAG Prompt Injection",
      severity: "high",
      description: "User input is used in RAG queries without proper sanitization",
      owaspCategory: OWASP_LLM_CATEGORIES.PROMPT_INJECTION,
      relatedComponents: vectorDBComponents.map(c => c.name),
      evidence: [],
      confidence: 0.9
    };
    
    // 2. RAG Data Leakage risk
    const dataLeakageRisk: SecurityRisk = {
      risk: "RAG Data Leakage",
      severity: "medium",
      description: "RAG implementation may leak sensitive information through vector retrieval",
      owaspCategory: OWASP_LLM_CATEGORIES.VECTOR_AND_EMBEDDING_WEAKNESSES,
      relatedComponents: vectorDBComponents.map(c => c.name),
      evidence: [],
      confidence: 0.85
    };
    
    // Find evidence for these risks
    for (const file of files) {
      const filePath = file.path;
      const importSet = imports.get(filePath);
      if (!importSet) continue;
      
      const lines = file.content.split('\n');
      
      // Check for vector DB query operations with user input
      if (vectorDBComponents.some(c => c.locations.some(loc => loc.file === filePath))) {
        // This file uses a vector DB - look for query operations
        const queryLines = lines
          .map((line, idx) => ({ line, idx }))
          .filter(({ line }) => 
            /\.query\s*\(/.test(line) && 
            /user|input|prompt|message|text/.test(line) &&
            !/sanitize|validate|clean/.test(line.toLowerCase())
          );
          
        if (queryLines.length > 0) {
          for (const { line, idx } of queryLines) {
            promptInjectionRisk.evidence.push({
              file: filePath,
              line: idx + 1,
              snippet: line.trim(),
              context: {
                before: lines.slice(Math.max(0, idx - 2), idx),
                after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
                scope: detectScope(lines, idx)
              }
            });
          }
        }
        
        // Check for vector DB upsert operations without data filtering
        const upsertLines = lines
          .map((line, idx) => ({ line, idx }))
          .filter(({ line }) => 
            /upsert|index|store/.test(line) && 
            !/filter|sanitize|redact/.test(line.toLowerCase())
          );
          
        if (upsertLines.length > 0) {
          for (const { line, idx } of upsertLines) {
            dataLeakageRisk.evidence.push({
              file: filePath,
              line: idx + 1,
              snippet: line.trim(),
              context: {
                before: lines.slice(Math.max(0, idx - 2), idx),
                after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
                scope: detectScope(lines, idx)
              }
            });
          }
        }
      }
    }
    
    // Only add risks if we found evidence
    if (promptInjectionRisk.evidence.length > 0) {
      risks.push(promptInjectionRisk);
    }
    
    if (dataLeakageRisk.evidence.length > 0) {
      risks.push(dataLeakageRisk);
    }
  }
  
  // Check for hardcoded API keys
  const apiKeyRisk: SecurityRisk = {
    risk: "Hardcoded API Keys",
    severity: "high",
    description: "API keys or credentials found directly in code",
    owaspCategory: OWASP_LLM_CATEGORIES.SUPPLY_CHAIN,
    relatedComponents: [],
    evidence: [],
    confidence: 0.95
  };
  
  for (const file of files) {
    const lines = file.content.split('\n');
    
    // Improve API key detection regex
    const apiKeyLines = lines
      .map((line, idx) => ({ line, idx }))
      .filter(({ line }) => {
        // More comprehensive API key detection
        const hasKeyIdentifier = /api[-_]?key|apikey|secret[-_]?key|token|auth[-_]?key/i.test(line);
        const hasKeyPattern = /=\s*["']([a-zA-Z0-9_\-\.]{20,})["']/.test(line) || 
                             /=\s*process\.env\.([A-Z_]+)/.test(line) ||
                             /=\s*Deno\.env\.get\(['"]([A-Z_]+)['"]\)/.test(line);
        return hasKeyIdentifier && hasKeyPattern && !line.includes('process.env');
      });
      
    if (apiKeyLines.length > 0) {
      for (const { line, idx } of apiKeyLines) {
        apiKeyRisk.evidence.push({
          file: file.path,
          line: idx + 1,
          snippet: line.trim(),
          context: {
            before: lines.slice(Math.max(0, idx - 2), idx),
            after: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
            scope: detectScope(lines, idx)
          }
        });
      }
    }
  }
  
  if (apiKeyRisk.evidence.length > 0) {
    risks.push(apiKeyRisk);
  }
  
  return risks;
} 

// Add the missing buildCallGraph function
function buildCallGraph(files: RepositoryFile[], components: AIComponent[]) {
  // Create nodes from components and files
  const nodes = Array.from(new Set([
    ...components.map(c => c.name),
    ...files.map(f => f.path.split('/').pop() || f.path)
      .filter(name => name.match(/\.(js|ts|py|jsx|tsx)$/))
  ]));
  
  // Create edges based on imports and component usage
  const edges: Array<{from: string, to: string, type: string}> = [];
  
  // Add edges between components that are used together
  for (const component of components) {
    for (const location of component.locations) {
      const file = location.file.split('/').pop() || location.file;
      if (!nodes.includes(file)) continue;
      
      edges.push({
        from: file,
        to: component.name,
        type: 'uses'
      });
    }
  }
  
  return {
    nodes,
    edges
  };
} 
