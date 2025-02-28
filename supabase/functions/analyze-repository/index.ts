
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { load } from "https://deno.land/std@0.204.0/dotenv/mod.ts";

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

async function fetchRepoFiles(repositoryUrl: string, maxFiles = 50): Promise<{path: string, content: string}[]> {
  // Extract owner and repo from URL
  const urlMatch = repositoryUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  if (!urlMatch) {
    throw new Error("Invalid GitHub repository URL");
  }
  
  const [_, owner, repo] = urlMatch;
  
  console.log(`Fetching repository structure for ${owner}/${repo}`);
  
  // Step 1: Fetch repository structure
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`;
  const response = await fetch(apiUrl);
  
  if (!response.ok) {
    // Try to fetch 'master' branch if 'main' doesn't exist
    const fallbackUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`;
    const fallbackResponse = await fetch(fallbackUrl);
    
    if (!fallbackResponse.ok) {
      throw new Error(`Failed to fetch repository structure: ${response.status} ${response.statusText}`);
    }
    
    const data = await fallbackResponse.json();
    return await processRepoTree(data, owner, repo, maxFiles);
  }
  
  const data = await response.json();
  return await processRepoTree(data, owner, repo, maxFiles);
}

async function processRepoTree(treeData: any, owner: string, repo: string, maxFiles: number): Promise<{path: string, content: string}[]> {
  // Filter for code files and limit to a reasonable number
  const codeExtensions = [
    '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.cpp', 
    '.c', '.cs', '.php', '.rb', '.swift', '.kt', '.rs'
  ];
  
  // Filter out files we don't want to analyze
  const codePaths = treeData.tree
    .filter((item: any) => {
      return item.type === 'blob' && 
             codeExtensions.some(ext => item.path.endsWith(ext)) &&
             !item.path.includes('node_modules/') &&
             !item.path.includes('dist/') &&
             !item.path.includes('build/') &&
             !item.path.includes('vendor/');
    })
    .map((item: any) => item.path)
    .slice(0, maxFiles); // Limit to maxFiles
  
  console.log(`Found ${codePaths.length} code files to analyze`);
  
  // Fetch content of selected files
  const fileContents = await Promise.all(
    codePaths.map(async (path: string) => {
      try {
        const fileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${path}`;
        const response = await fetch(fileUrl);
        
        if (!response.ok) {
          // Try master branch as fallback
          const fallbackUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${path}`;
          const fallbackResponse = await fetch(fallbackUrl);
          
          if (!fallbackResponse.ok) {
            console.warn(`Failed to fetch file ${path}: ${response.status}`);
            return { path, content: "" };
          }
          
          const content = await fallbackResponse.text();
          return { path, content };
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

async function analyzeRepositoryWithOpenAI(repoFiles: {path: string, content: string}[], systemPrompt: string): Promise<RepositoryAnalysis> {
  if (!openAIApiKey) {
    throw new Error("OpenAI API key is not configured. Please set the OPENAI_API_KEY environment variable.");
  }
  
  console.log("Preparing repository data for analysis...");
  
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
  const MAX_BATCH_SIZE = 10;
  const fileBatches = [];
  for (let i = 0; i < filesForAnalysis.length; i += MAX_BATCH_SIZE) {
    fileBatches.push(filesForAnalysis.slice(i, i + MAX_BATCH_SIZE));
  }
  
  console.log(`Created ${fileBatches.length} batches of files for analysis`);
  
  let allAnalysisResults: any[] = [];
  
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
            content: systemPrompt || `You are an expert code analyzer specializing in identifying AI components and security risks in code repositories. Analyze the provided code files and identify:
            1. AI components or integrations
            2. Security risks or vulnerabilities
            3. Specific code references (file, line, snippet) that support your findings
            
            Only identify verifiable patterns in the actual code provided. Do not hallucinate or invent findings.`
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
  
  // Consolidate all batch results
  return consolidateAnalysisResults(allAnalysisResults);
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
              ...existingRisk.related_code_references,
              ...risk.related_code_references
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
  
  // Connect code references to security risks if not already connected
  result.code_references.forEach(codeRef => {
    if (codeRef.relatedRisks && codeRef.relatedRisks.length > 0) {
      codeRef.relatedRisks.forEach(riskName => {
        const risk = result.security_risks.find(r => r.risk === riskName);
        if (risk) {
          if (!risk.related_code_references.includes(codeRef.id)) {
            risk.related_code_references.push(codeRef.id);
          }
        }
      });
    }
  });
  
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
