import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Get environment variables
const openAIApiKey = Deno.env.get('OPENAI_API_KEY');

// Type definitions for the repository analysis response
interface RepositoryAnalysis {
  ai_components_detected: {
    name: string;
    type: string;
    confidence: number;
  }[];
  security_risks: {
    risk: string;
    severity: string;
    description: string;
    related_code_references: string[]; // IDs of related code references
  }[];
  code_references: {
    id: string; // Unique ID for each reference
    file: string;
    line: number;
    snippet: string;
    verified: boolean;
    relatedRisks?: string[]; // Risk names this reference is related to
  }[];
  confidence_score: number;
  remediation_suggestions: string[];
}

async function fetchRepoFiles(repositoryUrl: string, maxFiles = 100): Promise<{path: string, content: string}[]> {
  // Extract owner and repo from URL
  const urlMatch = repositoryUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  if (!urlMatch) {
    throw new Error("Invalid GitHub repository URL");
  }
  
  const [_, owner, repo] = urlMatch;
  
  console.log(`Fetching repository structure for ${owner}/${repo}`);
  
  // Step 1: Check if repo exists and get default branch
  const repoInfoUrl = `https://api.github.com/repos/${owner}/${repo}`;
  const repoInfoResponse = await fetch(repoInfoUrl);
  
  if (!repoInfoResponse.ok) {
    throw new Error(`Repository not found: ${repoInfoResponse.status} ${repoInfoResponse.statusText}`);
  }
  
  const repoInfo = await repoInfoResponse.json();
  console.log(`Repository exists. Stars: ${repoInfo.stargazers_count}, Language: ${repoInfo.language}`);
  
  const defaultBranch = repoInfo.default_branch;
  
  // Step 2: Fetch repository structure
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`;
  const response = await fetch(apiUrl);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch repository structure: ${response.status} ${response.statusText}`);
  }
  
  const data = await response.json();
  return await processRepoTree(data, owner, repo, defaultBranch, maxFiles);
}

async function processRepoTree(treeData: any, owner: string, repo: string, branch: string, maxFiles: number): Promise<{path: string, content: string}[]> {
  // Important metadata files that indicate dependencies and configs
  const metadataFiles = [
    'requirements.txt',
    'package.json',
    'Pipfile',
    'pyproject.toml',
    'setup.py',
    'environment.yml',
    'conda.yml',
    'Gemfile',
    'pom.xml',
    'build.gradle',
    'docker-compose.yml',
    'Dockerfile',
    '.env.example',
    'config.py',
    'settings.py'
  ];
  
  // Code file extensions to include
  const codeExtensions = [
    '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.cpp', 
    '.c', '.cs', '.php', '.rb', '.swift', '.kt', '.rs', '.ipynb'
  ];
  
  // First, prioritize metadata files
  const metadataPaths = treeData.tree
    .filter((item: any) => {
      return item.type === 'blob' && 
             metadataFiles.some(file => 
               item.path === file || item.path.endsWith(`/${file}`)
             );
    })
    .map((item: any) => item.path);
  
  console.log(`Found ${metadataPaths.length} metadata files`);
  
  // Then, add code files
  const codePaths = treeData.tree
    .filter((item: any) => {
      return item.type === 'blob' && 
             codeExtensions.some(ext => item.path.endsWith(ext)) &&
             !item.path.includes('node_modules/') &&
             !item.path.includes('dist/') &&
             !item.path.includes('build/') &&
             !item.path.includes('vendor/');
    })
    .map((item: any) => item.path);
  
  console.log(`Found ${codePaths.length} code files`);
  
  // Combine and limit to maxFiles, ensuring metadata files are included
  const selectedPaths = [...metadataPaths, ...codePaths].slice(0, maxFiles);
  
  console.log(`Selected ${selectedPaths.length} files to analyze`);
  
  // Fetch content of selected files
  const fileContents = await Promise.all(
    selectedPaths.map(async (path: string) => {
      try {
        const fileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
        const response = await fetch(fileUrl);
        
        if (!response.ok) {
          console.warn(`Failed to fetch file ${path}: ${response.status}`);
          return { path, content: "" };
        }
        
        const content = await response.text();
        return { path, content };
      } catch (error) {
        console.warn(`Error fetching ${path}: ${error.message}`);
        return { path, content: "" };
      }
    })
  );
  
  // Filter out empty files
  return fileContents.filter(file => file.content);
}

async function analyzeRepositoryWithOpenAI(
  repoFiles: {path: string, content: string}[], 
  systemPrompt: string
): Promise<RepositoryAnalysis> {
  if (!openAIApiKey) {
    throw new Error("OpenAI API key is not configured. Please set the OPENAI_API_KEY environment variable.");
  }
  
  console.log("Preparing repository data for analysis...");
  
  // Pre-analyze metadata files to extract AI components
  const metadataComponents = extractAIComponentsFromMetadata(repoFiles);
  console.log(`Pre-extracted ${metadataComponents.length} AI components from metadata files`);
  
  // Prepare repository content for analysis
  // Truncate file content to avoid token limits
  const MAX_CHARS_PER_FILE = 5000;
  const filesForAnalysis = repoFiles.map(file => {
    const truncatedContent = file.content.length > MAX_CHARS_PER_FILE 
      ? file.content.substring(0, MAX_CHARS_PER_FILE) + "... [truncated]" 
      : file.content;
    
    return `File path: ${file.path}\n\n${truncatedContent}\n\n`;
  });
  
  // Create batches of files to avoid token limits
  const MAX_BATCH_SIZE = 5;
  const fileBatches = [];
  for (let i = 0; i < filesForAnalysis.length; i += MAX_BATCH_SIZE) {
    fileBatches.push(filesForAnalysis.slice(i, i + MAX_BATCH_SIZE));
  }
  
  console.log(`Created ${fileBatches.length} batches of files for analysis`);
  
  let allAnalysisResults: any[] = [];
  
  // Enhance system prompt with detected components
  let enhancedSystemPrompt = systemPrompt;
  if (metadataComponents.length > 0) {
    enhancedSystemPrompt += `\n\nIMPORTANT: I've already identified these AI components from metadata files:\n`;
    metadataComponents.forEach(comp => {
      enhancedSystemPrompt += `- ${comp.name} (${comp.type})\n`;
    });
    enhancedSystemPrompt += `\nPlease consider these as confirmed components with high confidence. Include them in your analysis along with any additional components you find in the code.`;
  }
  
  // Process each batch
  for (let i = 0; i < fileBatches.length; i++) {
    const batch = fileBatches[i];
    console.log(`Analyzing batch ${i+1}/${fileBatches.length} with ${batch.length} files...`);
    
    const batchContent = batch.join("\n---FILE SEPARATOR---\n\n");
    
    // Call OpenAI API for analysis
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${openAIApiKey}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini", // Using GPT-4o-mini for better analysis at reasonable cost
        messages: [
          {
            role: "system",
            content: enhancedSystemPrompt
          },
          {
            role: "user",
            content: `Analyze the following code repository files and provide a detailed analysis in JSON format. Focus on identifying AI components and security risks with specific code references.\n\n${batchContent}`
          }
        ],
        temperature: 0.1,
        response_format: { type: "json_object" }
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`OpenAI API error: ${response.status} ${response.statusText}`, errorText);
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }
    
    const result = await response.json();
    const analysisContent = result.choices[0].message.content;
    
    try {
      const batchAnalysis = JSON.parse(analysisContent);
      allAnalysisResults.push(batchAnalysis);
    } catch (e) {
      console.error("Failed to parse OpenAI response:", e);
      console.log("Raw response:", analysisContent);
      throw new Error("Failed to parse analysis results from OpenAI");
    }
  }
  
  console.log("Consolidating analysis results...");
  
  // Add pre-detected components to results
  if (metadataComponents.length > 0) {
    const metadataResult = {
      ai_components_detected: metadataComponents,
      security_risks: [],
      code_references: [],
      confidence_score: 0.98,
      remediation_suggestions: []
    };
    allAnalysisResults.push(metadataResult);
  }
  
  // Consolidate all batch results
  const consolidatedResults = consolidateAnalysisResults(allAnalysisResults);
  
  // Adjust confidence score based on detected components
  if (consolidatedResults.ai_components_detected.length > 0) {
    consolidatedResults.confidence_score = Math.max(
      consolidatedResults.confidence_score,
      0.7 + Math.min(0.28, consolidatedResults.ai_components_detected.length * 0.04)
    );
  }
  
  return consolidatedResults;
}

// Helper function to extract AI components from metadata files
function extractAIComponentsFromMetadata(files: {path: string, content: string}[]): any[] {
  const aiComponents: {name: string, type: string, confidence: number}[] = [];
  const aiLibraries = [
    // General AI/ML
    {name: 'tensorflow', display: 'TensorFlow', type: 'ML Framework'},
    {name: 'torch', display: 'PyTorch', type: 'ML Framework'},
    {name: 'keras', display: 'Keras', type: 'ML Framework'},
    {name: 'scikit-learn', display: 'Scikit-learn', type: 'ML Framework'},
    {name: 'sklearn', display: 'Scikit-learn', type: 'ML Framework'},
    {name: 'xgboost', display: 'XGBoost', type: 'ML Algorithm'},
    {name: 'lightgbm', display: 'LightGBM', type: 'ML Algorithm'},
    {name: 'catboost', display: 'CatBoost', type: 'ML Algorithm'},
    
    // NLP & LLMs
    {name: 'transformers', display: 'Hugging Face Transformers', type: 'NLP Library'},
    {name: 'langchain', display: 'LangChain', type: 'LLM Framework'},
    {name: 'llama-index', display: 'LlamaIndex', type: 'RAG Framework'},
    {name: 'openai', display: 'OpenAI API', type: 'LLM Provider'},
    {name: 'tiktoken', display: 'Tiktoken', type: 'OpenAI Tokenizer'},
    {name: 'anthropic', display: 'Anthropic API', type: 'LLM Provider'},
    {name: 'cohere', display: 'Cohere API', type: 'LLM Provider'},
    {name: 'ai21', display: 'AI21 Labs API', type: 'LLM Provider'},
    {name: 'gpt4all', display: 'GPT4All', type: 'Local LLM'},
    {name: 'llama-cpp', display: 'Llama.cpp', type: 'Local LLM'},
    {name: 'ollama', display: 'Ollama', type: 'Local LLM Platform'},
    {name: 'llamaindex', display: 'LlamaIndex', type: 'RAG Framework'},
    {name: 'sentence-transformers', display: 'Sentence Transformers', type: 'Embedding Model'},
    {name: 'spacy', display: 'spaCy', type: 'NLP Library'},
    {name: 'nltk', display: 'NLTK', type: 'NLP Library'},
    {name: 'gensim', display: 'Gensim', type: 'NLP Library'},
    {name: 'google-genai', display: 'Google Generative AI (Gemini)', type: 'LLM Provider'},
    
    // Vector DBs
    {name: 'faiss', display: 'FAISS', type: 'Vector Database'},
    {name: 'pinecone', display: 'Pinecone', type: 'Vector Database'},
    {name: 'chroma', display: 'ChromaDB', type: 'Vector Database'},
    {name: 'qdrant', display: 'Qdrant', type: 'Vector Database'},
    {name: 'weaviate', display: 'Weaviate', type: 'Vector Database'},
    {name: 'milvus', display: 'Milvus', type: 'Vector Database'},
    {name: 'pgvector', display: 'PGVector', type: 'Vector Extension'},
    
    // Computer Vision
    {name: 'opencv', display: 'OpenCV', type: 'Computer Vision'},
    {name: 'pillow', display: 'Pillow', type: 'Image Processing'},
    {name: 'detectron2', display: 'Detectron2', type: 'Computer Vision'},
    {name: 'timm', display: 'PyTorch Image Models', type: 'Computer Vision'},
    
    // JS Libraries
    {name: '@huggingface', display: 'Hugging Face JS', type: 'AI Library'},
    {name: '@tensorflow', display: 'TensorFlow.js', type: 'ML Framework'},
    {name: 'ml5', display: 'ml5.js', type: 'ML Library'},
    {name: 'brain.js', display: 'Brain.js', type: 'Neural Network Library'},
    {name: 'langchainjs', display: 'LangChain.js', type: 'LLM Framework'},
    {name: '@langchain', display: 'LangChain.js', type: 'LLM Framework'}
  ];
  
  for (const file of files) {
    // Skip non-metadata files
    if (!isMetadataFile(file.path)) continue;
    
    const content = file.content;
    
    if (file.path.endsWith('requirements.txt') || file.path.endsWith('Pipfile') || file.path.endsWith('pyproject.toml')) {
      // Python dependencies
      for (const lib of aiLibraries) {
        const regex = new RegExp(`(?:^|\\n|\\r)${lib.name}(?:[=><~\\[\\s]|$)`, 'i');
        if (regex.test(content)) {
          aiComponents.push({
            name: lib.display,
            type: lib.type,
            confidence: 0.98
          });
        }
      }
    } else if (file.path.endsWith('package.json')) {
      // JavaScript dependencies
      try {
        const packageJson = JSON.parse(content);
        const dependencies = {
          ...(packageJson.dependencies || {}),
          ...(packageJson.devDependencies || {})
        };
        
        for (const [dep, version] of Object.entries(dependencies)) {
          for (const lib of aiLibraries) {
            if (dep === lib.name || dep.includes(lib.name)) {
              aiComponents.push({
                name: lib.display,
                type: lib.type,
                confidence: 0.98
              });
              break;
            }
          }
        }
      } catch (e) {
        // Handle JSON parse error
        console.error(`Error parsing package.json: ${e}`);
      }
    }
  }
  
  // Remove duplicates
  const uniqueComponents = aiComponents.filter((comp, index, self) =>
    index === self.findIndex((c) => c.name === comp.name)
  );
  
  return uniqueComponents;
}

function isMetadataFile(path: string): boolean {
  const metadataPatterns = [
    /requirements\.txt$/,
    /package\.json$/,
    /Pipfile$/,
    /pyproject\.toml$/,
    /setup\.py$/,
    /environment\.yml$/,
    /conda\.yml$/,
    /Gemfile$/,
    /pom\.xml$/,
    /build\.gradle$/,
    /Dockerfile$/
  ];
  
  return metadataPatterns.some(pattern => pattern.test(path));
}

function consolidateAnalysisResults(batchResults: any[]): RepositoryAnalysis {
  const result: RepositoryAnalysis = {
    ai_components_detected: [],
    security_risks: [],
    code_references: [],
    confidence_score: 0,
    remediation_suggestions: []
  };
  
  const aiComponentsMap = new Map();
  const securityRisksMap = new Map();
  const codeReferencesMap = new Map();
  const suggestionsSet = new Set();
  
  // Process and deduplicate each batch
  let totalConfidence = 0;
  let confidenceCount = 0;
  
  batchResults.forEach(batch => {
    // Handle AI components
    if (batch.ai_components || batch.ai_components_detected) {
      const components = batch.ai_components_detected || batch.ai_components || [];
      components.forEach((comp: any) => {
        const key = comp.name.toLowerCase();
        if (!aiComponentsMap.has(key)) {
          aiComponentsMap.set(key, comp);
        } else if (comp.confidence > aiComponentsMap.get(key).confidence) {
          // Keep the component with higher confidence
          aiComponentsMap.set(key, comp);
        }
      });
    }
    
    // Handle security risks
    if (batch.security_risks) {
      batch.security_risks.forEach((risk: any) => {
        const key = risk.risk.toLowerCase();
        if (!securityRisksMap.has(key)) {
          // Ensure the risk has related_code_references property
          const enhancedRisk = {
            ...risk,
            related_code_references: risk.related_code_references || []
          };
          securityRisksMap.set(key, enhancedRisk);
        } else {
          // Merge related code references
          const existingRisk = securityRisksMap.get(key);
          if (risk.related_code_references) {
            existingRisk.related_code_references = [
              ...new Set([
                ...existingRisk.related_code_references,
                ...risk.related_code_references
              ])
            ];
          }
        }
      });
    }
    
    // Handle code references
    if (batch.code_references) {
      batch.code_references.forEach((ref: any, index: number) => {
        // Generate a unique ID if it doesn't exist
        const id = ref.id || `ref-${codeReferencesMap.size + index + 1}`;
        const key = `${ref.file}-${ref.line}`;
        
        if (!codeReferencesMap.has(key)) {
          const enhancedRef = {
            ...ref,
            id,
            verified: ref.verified !== undefined ? ref.verified : true,
            relatedRisks: ref.relatedRisks || []
          };
          codeReferencesMap.set(key, enhancedRef);
        }
      });
    }
    
    // Handle remediation suggestions
    if (batch.remediation_suggestions) {
      batch.remediation_suggestions.forEach((suggestion: string) => {
        suggestionsSet.add(suggestion);
      });
    }
    
    // Accumulate confidence scores
    if (batch.confidence_score !== undefined) {
      totalConfidence += batch.confidence_score;
      confidenceCount++;
    }
  });
  
  // Build the final consolidated analysis
  result.ai_components_detected = Array.from(aiComponentsMap.values());
  result.security_risks = Array.from(securityRisksMap.values());
  result.code_references = Array.from(codeReferencesMap.values());
  result.remediation_suggestions = Array.from(suggestionsSet);
  
  // Calculate average confidence score
  result.confidence_score = confidenceCount > 0 ? totalConfidence / confidenceCount : 0.5;
  
  // Establish bidirectional relationships
  // Connect security risks to code references
  result.security_risks.forEach(risk => {
    if (risk.related_code_references) {
      risk.related_code_references.forEach(refId => {
        const codeRef = result.code_references.find(ref => ref.id === refId);
        if (codeRef) {
          if (!codeRef.relatedRisks) {
            codeRef.relatedRisks = [];
          }
          if (!codeRef.relatedRisks.includes(risk.risk)) {
            codeRef.relatedRisks.push(risk.risk);
          }
        }
      });
    }
  });
  
  // Add security risks based on AI components
  if (result.ai_components_detected.length > 0) {
    // Check for RAG components
    const hasRagComponents = result.ai_components_detected.some(comp => 
      ['Vector Database', 'RAG Framework', 'Embedding Model'].includes(comp.type)
    );
    
    // Check for LLM usage
    const hasLlmComponents = result.ai_components_detected.some(comp =>
      ['LLM Provider', 'LLM Framework', 'Local LLM'].includes(comp.type)
    );
    
    // Add data leakage risk if both RAG and LLM components are present
    if (hasRagComponents && hasLlmComponents) {
      const leakageRiskKey = 'data leakage via llm';
      if (!securityRisksMap.has(leakageRiskKey)) {
        result.security_risks.push({
          risk: "Potential for Data Leakage via LLM",
          severity: "High",
          description: "The application combines RAG (Retrieval Augmented Generation) with LLM usage, which could potentially lead to sensitive data leakage if proper safeguards are not in place.",
          related_code_references: []
        });
      }
    }
    
    // Add prompt injection risk if LLM components are present
    if (hasLlmComponents) {
      const injectionRiskKey = 'prompt injection';
      if (!securityRisksMap.has(injectionRiskKey)) {
        result.security_risks.push({
          risk: "Prompt Injection Vulnerability",
          severity: "Medium",
          description: "The application uses LLMs and may be vulnerable to prompt injection attacks if user inputs are not properly sanitized before being sent to the model.",
          related_code_references: []
        });
      }
    }
    
    // Add remediation suggestions based on detected risks
    if (hasRagComponents && hasLlmComponents) {
      result.remediation_suggestions.push(
        "Implement input validation and sanitization for all user inputs before passing to LLMs",
        "Consider adding a content filter for LLM outputs to prevent sensitive data leakage",
        "Use role-based access control for sensitive RAG data sources"
      );
    }
  }
  
  return result;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse request body
    const reqData = await req.json();
    const repositoryUrl = reqData.repositoryUrl;
    const options = reqData.options || {};
    
    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: "Repository URL is required" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 400 }
      );
    }
    
    if (!openAIApiKey) {
      return new Response(
        JSON.stringify({ 
          error: "OpenAI API key is not configured. Please set the OPENAI_API_KEY in Supabase Edge Function secrets."
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 500 }
      );
    }
    
    console.log(`Analyzing repository: ${repositoryUrl}`);
    
    // Step 1: Fetch repository files
    const repoFiles = await fetchRepoFiles(repositoryUrl);
    
    // Step 2: Analyze repository using OpenAI
    const systemPrompt = options.systemPrompt || `
      You are an expert code analyzer specializing in identifying AI components and security risks in code repositories.
      
      Analyze the provided code files to identify:
      1. AI components or integrations (libraries, APIs, models) with confidence levels
      2. Security risks with severity levels and detailed descriptions
      3. Specific code references that support your findings (must be actual code in the repository)
      
      Your response must follow this exact JSON format:
      {
        "ai_components_detected": [
          {"name": "Component Name", "type": "Type (API/Library/etc)", "confidence": 0.95}
        ],
        "security_risks": [
          {"risk": "Risk Name", "severity": "Critical/High/Medium/Low", "description": "Detailed description", "related_code_references": ["ref-id"]}
        ],
        "code_references": [
          {"id": "unique-ref-id", "file": "filepath", "line": 42, "snippet": "actual code snippet", "verified": true}
        ],
        "confidence_score": 0.85,
        "remediation_suggestions": ["Suggestion 1", "Suggestion 2"]
      }
      
      For AI components, focus specifically on:
      - LLM integrations (OpenAI, Anthropic, Cohere, etc.)
      - Vector databases (FAISS, Pinecone, Weaviate, ChromaDB, Qdrant)
      - Embedding models and services
      - RAG (Retrieval Augmented Generation) implementations
      - ML frameworks (TensorFlow, PyTorch, etc.)
      
      For security risks, pay special attention to:
      - Prompt injection vulnerabilities
      - Potential for data leakage through LLMs
      - Hard-coded API keys or secrets
      - Insecure handling of user inputs to AI services
      
      Only identify verifiable patterns in the actual code provided. Never invent or hallucinate file paths or code snippets.
      Assign each code reference a unique ID starting with "ref-" followed by a number.
      Include "related_code_references" arrays in security risks containing the IDs of relevant code references.
    `;
    
    const analysis = await analyzeRepositoryWithOpenAI(repoFiles, systemPrompt);
    
    console.log("Analysis complete!");
    
    return new Response(
      JSON.stringify(analysis),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
    
  } catch (error) {
    console.error("Error analyzing repository:", error);
    
    return new Response(
      JSON.stringify({ error: error.message || "Failed to analyze repository" }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 500 }
    );
  }
});
