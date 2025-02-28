
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

// Configuration for GitHub API requests
const GITHUB_API_TOKEN = Deno.env.get("GITHUB_API_TOKEN") || "";

// CORS headers for cross-origin requests
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Function to check if text contains AI-related keywords
function containsAIKeywords(text: string): boolean {
  const aiKeywords = [
    'openai', 'gpt', 'chatgpt', 'llm', 'large language model', 'stable diffusion',
    'machine learning', 'artificial intelligence', 'neural network', 'deep learning',
    'tensorflow', 'pytorch', 'keras', 'huggingface', 'transformers', 'langchain',
    'vector database', 'embeddings', 'whisper', 'dall-e', 'midjourney', 'anthropic',
    'claude', 'mistral', 'llama', 'gemini'
  ];
  
  const textLower = text.toLowerCase();
  return aiKeywords.some(keyword => textLower.includes(keyword.toLowerCase()));
}

// Function to analyze Python file for API keys
function detectApiKeys(content: string): { found: boolean; line?: number; snippet?: string } {
  const apiKeyPatterns = [
    /['"](?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}['"]/g,  // Stripe
    /['"](?:sk)-[0-9a-zA-Z]{48}['"]/g,  // OpenAI
    /['"](?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}['"]/g,  // GitHub
    /['"][0-9a-f]{32}['"]/g,  // Generic hex API key
    /['"][0-9a-zA-Z_\-]{21,40}['"]/g,  // Generic alphanumeric
    /api(?:[-_]?key|[-_]?token)(?:\s*=\s*|\s*:\s*)['"][0-9a-zA-Z_\-\.]{16,}['"]/gi,  // Named variables
  ];

  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    for (const pattern of apiKeyPatterns) {
      if (pattern.test(line)) {
        return {
          found: true,
          line: i + 1,
          snippet: line.trim()
        };
      }
    }
  }
  
  return { found: false };
}

// Function to scan a repository
async function scanRepository(repoUrl: string) {
  // Parse owner and repo from URL
  const urlMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  if (!urlMatch) {
    throw new Error("Invalid GitHub repository URL");
  }
  
  const [, owner, repo] = urlMatch;
  
  // GitHub API base URL
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}`;
  
  // Fetch repository info
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github.v3+json",
  };
  
  if (GITHUB_API_TOKEN) {
    headers["Authorization"] = `token ${GITHUB_API_TOKEN}`;
  }
  
  // Get repository information
  const repoResponse = await fetch(apiUrl, { headers });
  if (!repoResponse.ok) {
    throw new Error(`GitHub API error: ${repoResponse.status} ${await repoResponse.text()}`);
  }
  
  // Get repository contents
  const contentsUrl = `${apiUrl}/contents`;
  const contentsResponse = await fetch(contentsUrl, { headers });
  if (!contentsResponse.ok) {
    throw new Error(`GitHub API error: ${contentsResponse.status} ${await contentsResponse.text()}`);
  }
  
  const contents = await contentsResponse.json();
  
  // Get file list recursively
  const files: { path: string; type: string; url: string }[] = [];
  await getFilesRecursively(contents, files, headers);
  
  // Analysis results
  const aiComponents: { name: string; type: string; confidence: number }[] = [];
  const securityRisks: { risk: string; severity: string; description: string }[] = [];
  const codeReferences: { file: string; line: number; snippet: string }[] = [];
  
  // Check package.json or requirements.txt for AI libraries
  for (const file of files) {
    if (file.path === 'package.json' || file.path === 'requirements.txt') {
      const fileResponse = await fetch(file.url, { headers });
      if (fileResponse.ok) {
        const fileData = await fileResponse.json();
        const content = atob(fileData.content);
        
        // Check for AI libraries
        detectAILibraries(content, file.path, aiComponents);
      }
    }
    
    // Scan Python, JavaScript, and TypeScript files for API keys and AI imports
    if (file.path.endsWith('.py') || file.path.endsWith('.js') || file.path.endsWith('.tsx') || file.path.endsWith('.ts')) {
      const fileResponse = await fetch(file.url, { headers });
      if (fileResponse.ok) {
        const fileData = await fileResponse.json();
        const content = atob(fileData.content);
        
        // Check for API keys
        const apiKeyCheck = detectApiKeys(content);
        if (apiKeyCheck.found) {
          securityRisks.push({
            risk: "API Key Exposure",
            severity: "Critical",
            description: `API key found in ${file.path}`
          });
          
          codeReferences.push({
            file: file.path,
            line: apiKeyCheck.line!,
            snippet: apiKeyCheck.snippet!
          });
        }
        
        // Check for AI imports/usage
        scanFileForAIUsage(content, file.path, aiComponents, codeReferences);
      }
    }
  }
  
  // Calculate confidence score based on findings
  let confidenceScore = Math.min(0.1 + (aiComponents.length * 0.15), 0.95);
  
  // Generate security risks based on AI components
  if (aiComponents.length > 0) {
    securityRisks.push({
      risk: "Potential for Prompt Injection",
      severity: "High",
      description: "AI components may be vulnerable to prompt injection attacks if user input is not properly sanitized"
    });
    
    securityRisks.push({
      risk: "Data Privacy Concerns",
      severity: "Medium",
      description: "AI systems may process sensitive data that could be exposed if not properly secured"
    });
  } else {
    // If no AI components were found
    securityRisks.push({
      risk: "No AI components detected",
      severity: "Info",
      description: "This repository does not appear to contain AI components"
    });
    confidenceScore = 0.05;
  }
  
  // Generate remediation suggestions
  const remediationSuggestions = generateRemediationSuggestions(aiComponents, securityRisks);
  
  return {
    ai_components_detected: aiComponents,
    security_risks: securityRisks,
    code_references: codeReferences,
    confidence_score: confidenceScore,
    remediation_suggestions: remediationSuggestions
  };
}

// Function to detect AI libraries in package files
function detectAILibraries(content: string, filePath: string, aiComponents: any[]) {
  const aiLibraries = {
    'openai': { type: 'LLM API', confidence: 0.98 },
    'langchain': { type: 'AI Framework', confidence: 0.95 },
    'transformers': { type: 'ML Framework', confidence: 0.9 },
    'tensorflow': { type: 'ML Framework', confidence: 0.9 },
    'pytorch': { type: 'ML Framework', confidence: 0.9 },
    'huggingface': { type: 'AI Ecosystem', confidence: 0.9 },
    'torch': { type: 'ML Framework', confidence: 0.9 },
    'keras': { type: 'ML Framework', confidence: 0.85 },
    'scikit-learn': { type: 'ML Framework', confidence: 0.8 },
    'nltk': { type: 'NLP Library', confidence: 0.7 },
    'spacy': { type: 'NLP Library', confidence: 0.8 },
    'gensim': { type: 'NLP Library', confidence: 0.7 },
    'anthropic': { type: 'LLM API', confidence: 0.95 },
    'cohere': { type: 'LLM API', confidence: 0.95 },
    'vertexai': { type: 'Cloud AI Service', confidence: 0.9 },
    'pinecone': { type: 'Vector Database', confidence: 0.85 },
    'chroma': { type: 'Vector Database', confidence: 0.85 },
    'weaviate': { type: 'Vector Database', confidence: 0.85 },
    'faiss': { type: 'Vector Search', confidence: 0.85 },
    'sentence-transformers': { type: 'ML Model', confidence: 0.85 },
  };
  
  if (filePath === 'package.json') {
    try {
      const packageJson = JSON.parse(content);
      const dependencies = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };
      
      for (const [lib, details] of Object.entries(aiLibraries)) {
        if (dependencies[lib]) {
          aiComponents.push({
            name: lib,
            type: details.type,
            confidence: details.confidence
          });
        }
      }
    } catch (e) {
      // Ignore JSON parsing errors
    }
  } else if (filePath === 'requirements.txt') {
    const lines = content.split('\n');
    
    for (const line of lines) {
      const libName = line.trim().split(/[=<>~]/)[0].trim().toLowerCase();
      
      if (aiLibraries[libName]) {
        aiComponents.push({
          name: libName,
          type: aiLibraries[libName].type,
          confidence: aiLibraries[libName].confidence
        });
      }
    }
  }
}

// Function to scan a file for AI usage patterns
function scanFileForAIUsage(content: string, filePath: string, aiComponents: any[], codeReferences: any[]) {
  const lines = content.split('\n');
  
  const aiPatterns = [
    { regex: /import\s+.*openai/i, name: 'OpenAI API', type: 'LLM API', confidence: 0.95 },
    { regex: /from\s+openai\s+import/i, name: 'OpenAI API', type: 'LLM API', confidence: 0.95 },
    { regex: /import\s+.*langchain/i, name: 'Langchain', type: 'AI Framework', confidence: 0.9 },
    { regex: /from\s+langchain\s+import/i, name: 'Langchain', type: 'AI Framework', confidence: 0.9 },
    { regex: /import\s+.*transformers/i, name: 'Hugging Face Transformers', type: 'ML Framework', confidence: 0.9 },
    { regex: /from\s+transformers\s+import/i, name: 'Hugging Face Transformers', type: 'ML Framework', confidence: 0.9 },
    { regex: /import\s+.*tensorflow/i, name: 'TensorFlow', type: 'ML Framework', confidence: 0.9 },
    { regex: /from\s+tensorflow\s+import/i, name: 'TensorFlow', type: 'ML Framework', confidence: 0.9 },
    { regex: /import\s+.*torch/i, name: 'PyTorch', type: 'ML Framework', confidence: 0.9 },
    { regex: /from\s+torch\s+import/i, name: 'PyTorch', type: 'ML Framework', confidence: 0.9 },
    { regex: /import\s+.*keras/i, name: 'Keras', type: 'ML Framework', confidence: 0.85 },
    { regex: /from\s+keras\s+import/i, name: 'Keras', type: 'ML Framework', confidence: 0.85 },
    { regex: /import\s+.*anthropic/i, name: 'Anthropic API', type: 'LLM API', confidence: 0.95 },
    { regex: /from\s+anthropic\s+import/i, name: 'Anthropic API', type: 'LLM API', confidence: 0.95 },
    { regex: /\.chat\.completions\.create/i, name: 'OpenAI Chat API', type: 'LLM API', confidence: 0.98 },
    { regex: /\.completions\.create/i, name: 'OpenAI Completions API', type: 'LLM API', confidence: 0.98 },
    { regex: /\.embeddings\.create/i, name: 'OpenAI Embeddings API', type: 'Embedding API', confidence: 0.98 },
    { regex: /\.images\.generate/i, name: 'OpenAI Image Generation', type: 'Image AI', confidence: 0.98 }
  ];
  
  const detectedComponents = new Set();
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    for (const pattern of aiPatterns) {
      if (pattern.regex.test(line)) {
        // Add to AI components if not already detected
        if (!detectedComponents.has(pattern.name)) {
          aiComponents.push({
            name: pattern.name,
            type: pattern.type,
            confidence: pattern.confidence
          });
          detectedComponents.add(pattern.name);
        }
        
        // Add code reference
        codeReferences.push({
          file: filePath,
          line: i + 1,
          snippet: line
        });
      }
    }
  }
}

// Function to generate remediation suggestions
function generateRemediationSuggestions(aiComponents: any[], securityRisks: any[]): string[] {
  const suggestions: string[] = [];
  
  if (aiComponents.length === 0) {
    return ["No AI-specific remediation needed"];
  }
  
  // Basic AI security recommendations
  suggestions.push("Use environment variables for API keys instead of hardcoding them");
  suggestions.push("Implement input validation before passing to LLM");
  suggestions.push("Set up content filtering for LLM inputs and outputs");
  
  // Based on detected risks
  const hasApiKeyRisk = securityRisks.some(risk => risk.risk.includes("API Key"));
  const hasPromptInjectionRisk = securityRisks.some(risk => risk.risk.includes("Prompt Injection"));
  
  if (hasApiKeyRisk) {
    suggestions.push("Rotate exposed API keys immediately");
    suggestions.push("Use a secrets manager for storing sensitive credentials");
  }
  
  if (hasPromptInjectionRisk) {
    suggestions.push("Implement a prompt engineering framework with security controls");
    suggestions.push("Use parameterized prompts instead of direct string concatenation");
  }
  
  // Check for specific AI components
  const hasLLM = aiComponents.some(comp => comp.type.includes("LLM"));
  const hasMLFramework = aiComponents.some(comp => comp.type.includes("ML Framework"));
  
  if (hasLLM) {
    suggestions.push("Implement rate limiting for API requests");
    suggestions.push("Set up monitoring for unusual usage patterns");
  }
  
  if (hasMLFramework) {
    suggestions.push("Ensure model weights and training data are properly secured");
    suggestions.push("Consider potential privacy implications when processing user data");
  }
  
  return suggestions;
}

// Helper function to recursively get all files in a repository
async function getFilesRecursively(
  contents: any[],
  files: { path: string; type: string; url: string }[],
  headers: Record<string, string>,
  path = ""
) {
  for (const item of contents) {
    const itemPath = path ? `${path}/${item.name}` : item.name;
    
    if (item.type === "file") {
      files.push({
        path: itemPath,
        type: "file",
        url: item.download_url || item._links?.git || item.url
      });
    } else if (item.type === "dir") {
      const dirResponse = await fetch(item.url, { headers });
      if (dirResponse.ok) {
        const dirContents = await dirResponse.json();
        await getFilesRecursively(dirContents, files, headers, itemPath);
      }
    }
  }
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  
  try {
    const { repositoryUrl } = await req.json();
    
    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: "Repository URL is required" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }
    
    // Validate that the URL is a GitHub repository
    const isGitHubUrl = /https?:\/\/github\.com\/[^\/]+\/[^\/]+/.test(repositoryUrl);
    if (!isGitHubUrl) {
      return new Response(
        JSON.stringify({ error: "URL must be a valid GitHub repository" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }
    
    // Create Supabase client
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );
    
    // Analyze the repository
    const analysisResult = await scanRepository(repositoryUrl);
    
    // Save the result to the database
    const { data, error } = await supabaseClient
      .from('repository_analyses')
      .insert({
        repository_url: repositoryUrl,
        analysis_result: analysisResult,
        created_at: new Date().toISOString()
      })
      .select();
    
    if (error) {
      console.error("Error saving to database:", error);
    }
    
    // Return the analysis result
    return new Response(
      JSON.stringify(analysisResult),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Error:", error.message);
    
    return new Response(
      JSON.stringify({ error: error.message }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
