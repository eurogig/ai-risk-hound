import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.4.0"

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
  // Step 1: Analyze package files first
  try {
    const packageComponents = analyzePackageFiles(content.files);
    
    // Use these findings to inform our code analysis
    const detectedLibraries = new Set(packageComponents.map(c => c.name));
    
    // Initialize graph for tracking relationships
    const callGraph: CallGraph = {
      nodes: [],
      edges: []
    };

    // Step 2: Scan for AI components and build initial graph
    const aiComponents: AIComponent[] = [];
    const detectedImports = new Map<string, Set<string>>(); // file -> imports

    for (const file of content.files) {
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

    // Step 3: Detect actual usage and update confidence
    const securityRisks: SecurityRisk[] = [];
    
    for (const file of content.files) {
      if (!detectedImports.has(file.path)) continue;

      const imports = detectedImports.get(file.path)!;
      const lines = file.content.split('\n');

      lines.forEach((line, lineIndex) => {
        // Check for model usage
        for (const [modelType, pattern] of Object.entries(AI_PATTERNS.models)) {
          if (pattern.test(line)) {
            // Add to risks if we find direct model usage
            securityRisks.push({
              risk: "Direct Model Usage",
              severity: "high",
              description: `Direct usage of ${modelType} model detected`,
              owaspCategory: OWASP_LLM_CATEGORIES.PROMPT_INJECTION,
              relatedComponents: Array.from(imports),
              evidence: [{
                file: file.path,
                line: lineIndex + 1,
                snippet: line.trim(),
                context: {
                  before: lines.slice(Math.max(0, lineIndex - 2), lineIndex),
                  after: lines.slice(lineIndex + 1, lineIndex + 3),
                  scope: detectScope(lines, lineIndex)
                }
              }],
              confidence: 0.95
            });
          }
        }

        // Check for system prompts
        for (const [promptType, pattern] of Object.entries(AI_PATTERNS.systemPrompts)) {
          if (pattern.test(line)) {
            securityRisks.push({
              risk: "System Prompt Exposure",
              severity: "medium",
              description: "Hardcoded system prompts detected",
              owaspCategory: OWASP_LLM_CATEGORIES.SYSTEM_PROMPT_LEAKAGE,
              relatedComponents: Array.from(imports),
              evidence: [{
                file: file.path,
                line: lineIndex + 1,
                snippet: line.trim(),
                context: {
                  before: lines.slice(Math.max(0, lineIndex - 2), lineIndex),
                  after: lines.slice(lineIndex + 1, lineIndex + 3),
                  scope: detectScope(lines, lineIndex)
                }
              }],
              confidence: 0.85
            });
          }
        }
      });
    }

    // Step 4: Generate summary
    const summary = {
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
    };

    const result: AnalysisResult = {
      repositoryName: content.repositoryName,
      timestamp: new Date().toISOString(),
      aiComponents,
      securityRisks,
      callGraph,
      summary
    };

    analysisCache.set(cacheKey, result);

    return result;
  } catch (error) {
    console.error('Error analyzing repository:', error);
    return {
      repositoryName: content.repositoryName,
      timestamp: new Date().toISOString(),
      aiComponents: [],
      securityRisks: [],
      callGraph: { nodes: [], edges: [] },
      summary: {
        totalAIUsage: 0,
        risksByLevel: { high: 0, medium: 0, low: 0 },
        topRisks: []
      }
    };
  }
}

// Add missing utility function
function detectScope(lines: string[], currentLine: number): string | undefined {
  // Look up for function/class definition
  for (let i = currentLine; i >= 0; i--) {
    const line = lines[i];
    if (!line) continue;
    
    const trimmedLine = line.trim();
    // Match function/class/method definitions across languages
    if (
      trimmedLine.match(/^(def|class|function|const|let|var|async function)\s+\w+/) ||
      trimmedLine.match(/^[public|private|protected].*\s+\w+\s*\(/) // Class methods
    ) {
      return trimmedLine;
    }
  }
  return "Global";
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

    if (!response.ok) {
      if (response.status === 403) {
        throw new Error('GitHub API rate limit exceeded. Please try again later.');
      }
      throw new Error(`GitHub API error: ${response.statusText}`);
    }

    const data = await response.json();
    
    // Filter for relevant files
    const relevantFiles = data.tree.filter(item => 
      item.type === 'blob' && (
        item.path.endsWith('.py') ||
        item.path.endsWith('.js') ||
        item.path.endsWith('.ts') ||
        item.path.endsWith('.tsx') ||
        item.path.endsWith('.jsx') ||
        item.path.endsWith('requirements.txt') ||
        item.path.endsWith('package.json')
      )
    );

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