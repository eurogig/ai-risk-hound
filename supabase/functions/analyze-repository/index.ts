import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { corsHeaders } from "../_shared/cors.ts";

interface AnalyzeRepositoryRequest {
  repositoryUrl: string;
  apiKey: string; // User-provided API key
  options?: {
    systemPrompt?: string;
  };
  debugMode?: boolean;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { repositoryUrl, apiKey, options, debugMode } = await req.json() as AnalyzeRepositoryRequest;

    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: "Repository URL is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!apiKey) {
      return new Response(
        JSON.stringify({ error: "API key is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Use the user-provided API key instead of the server's API key
    const openaiApiKey = apiKey;

    // Extract owner and repo from the GitHub URL
    const urlPattern = /github\.com\/([^\/]+)\/([^\/]+)/;
    const match = repositoryUrl.match(urlPattern);
    
    if (!match) {
      return new Response(
        JSON.stringify({ error: "Invalid GitHub repository URL format" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    
    const [, owner, repo] = match;
    console.log(`Analyzing repository: ${owner}/${repo}`);
    
    // Fetch repository contents using GitHub API
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`;
    console.log(`Fetching repository structure from: ${apiUrl}`);
    
    const response = await fetch(apiUrl, {
      headers: {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RiskRover-Repository-Analyzer",
      },
    });
    
    if (!response.ok) {
      // Try with 'master' branch if 'main' fails
      const masterApiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`;
      console.log(`Trying master branch: ${masterApiUrl}`);
      
      const masterResponse = await fetch(masterApiUrl, {
        headers: {
          "Accept": "application/vnd.github.v3+json",
          "User-Agent": "RiskRover-Repository-Analyzer",
        },
      });
      
      if (!masterResponse.ok) {
        throw new Error(`Failed to fetch repository contents: ${response.statusText}`);
      }
      
      const data = await masterResponse.json();
      return await analyzeRepositoryContents(data, owner, repo, openaiApiKey, options?.systemPrompt, debugMode);
    }
    
    const data = await response.json();
    return await analyzeRepositoryContents(data, owner, repo, openaiApiKey, options?.systemPrompt, debugMode);
  } catch (error) {
    console.error("Error in analyze-repository function:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Internal Server Error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

async function analyzeRepositoryContents(
  repoData: any,
  owner: string,
  repo: string,
  apiKey: string,
  systemPrompt?: string,
  debugMode?: boolean
) {
  // Extract file paths from the repository data
  const files = repoData.tree
    .filter((item: any) => item.type === "blob")
    .map((item: any) => item.path);
  
  console.log(`Found ${files.length} files in the repository`);
  
  // Prepare repository summary for the AI
  const fileExtensions = new Map<string, number>();
  files.forEach((file: string) => {
    const ext = file.split('.').pop()?.toLowerCase() || 'unknown';
    fileExtensions.set(ext, (fileExtensions.get(ext) || 0) + 1);
  });
  
  const extensionSummary = Array.from(fileExtensions.entries())
    .map(([ext, count]) => `${ext}: ${count} files`)
    .join('\n');
  
  // Identify important files for AI analysis
  const importantFiles = files.filter((file: string) => {
    const lowerFile = file.toLowerCase();
    return (
      lowerFile.includes('requirements.txt') ||
      lowerFile.includes('package.json') ||
      lowerFile.includes('setup.py') ||
      lowerFile.includes('dockerfile') ||
      lowerFile.includes('docker-compose') ||
      lowerFile.endsWith('.py') ||
      lowerFile.endsWith('.js') ||
      lowerFile.endsWith('.ts') ||
      lowerFile.endsWith('.jsx') ||
      lowerFile.endsWith('.tsx')
    );
  });
  
  // Fetch content of important files
  const fileContents = [];
  const maxFilesToFetch = 20; // Limit to prevent overloading
  
  for (let i = 0; i < Math.min(importantFiles.length, maxFilesToFetch); i++) {
    const filePath = importantFiles[i];
    try {
      const fileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${filePath}`;
      const response = await fetch(fileUrl);
      
      if (!response.ok) {
        // Try with master branch
        const masterFileUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${filePath}`;
        const masterResponse = await fetch(masterFileUrl);
        
        if (!masterResponse.ok) {
          console.log(`Failed to fetch file: ${filePath}`);
          continue;
        }
        
        const content = await masterResponse.text();
        fileContents.push({ path: filePath, content: content.slice(0, 10000) }); // Limit content size
      } else {
        const content = await response.text();
        fileContents.push({ path: filePath, content: content.slice(0, 10000) }); // Limit content size
      }
    } catch (error) {
      console.error(`Error fetching file ${filePath}:`, error);
    }
  }
  
  // Prepare repository information for AI analysis
  const repoInfo = {
    owner,
    repo,
    fileCount: files.length,
    fileExtensionSummary: extensionSummary,
    importantFiles: importantFiles.slice(0, 100).join('\n'), // Limit list size
    fileContents,
  };
  
  // Default system prompt if none provided
  const defaultSystemPrompt = `Analyze the GitHub repository and identify AI components and security risks.
  Focus on identifying:
  1. AI libraries and frameworks (OpenAI, LangChain, HuggingFace, etc.)
  2. Vector databases (FAISS, Pinecone, Weaviate, etc.)
  3. Embedding generation
  4. Security risks related to AI usage
  5. Potential for data leakage
  
  Provide specific code references when possible.`;
  
  // Call OpenAI API for analysis
  const openaiResponse = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-4-turbo-preview",
      messages: [
        {
          role: "system",
          content: systemPrompt || defaultSystemPrompt,
        },
        {
          role: "user",
          content: `Analyze this GitHub repository: ${owner}/${repo}\n\nRepository information:\n${JSON.stringify(repoInfo, null, 2)}`,
        },
      ],
      temperature: 0.1,
      max_tokens: 4000,
    }),
  });
  
  if (!openaiResponse.ok) {
    const errorData = await openaiResponse.json();
    throw new Error(`OpenAI API error: ${JSON.stringify(errorData)}`);
  }
  
  const aiResult = await openaiResponse.json();
  const analysisText = aiResult.choices[0].message.content;
  
  // Process the AI's analysis into structured format
  try {
    // Extract structured data from the AI's text response
    const structuredAnalysis = await extractStructuredData(analysisText, apiKey);
    
    // Add debug information if requested
    const result = {
      repository_url: `https://github.com/${owner}/${repo}`,
      ...structuredAnalysis,
    };
    
    if (debugMode) {
      result.debug = {
        file_count: files.length,
        important_files_analyzed: fileContents.length,
        ai_response_length: analysisText.length,
        raw_ai_response: analysisText.slice(0, 1000) + "...", // Truncated for brevity
      };
    }
    
    return new Response(
      JSON.stringify(result),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error processing AI analysis:", error);
    
    // Return a simplified result if structured extraction fails
    return new Response(
      JSON.stringify({
        repository_url: `https://github.com/${owner}/${repo}`,
        raw_analysis: analysisText,
        error: "Failed to structure analysis results",
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

async function extractStructuredData(analysisText: string, apiKey: string) {
  // Use OpenAI to convert the text analysis into structured JSON
  const structuringPrompt = `
  Convert the following repository analysis into a structured JSON object with these fields:
  
  1. summary: A concise summary of the repository's AI capabilities
  2. ai_components_detected: Array of AI components found (e.g., "OpenAI", "LangChain", etc.)
  3. security_risks: Array of security risks identified
  4. code_references: Array of objects with {file, line_number, code, description} for relevant code
  5. recommendations: Array of security recommendations
  
  Analysis text:
  ${analysisText}
  
  Return ONLY valid JSON without any explanation or markdown formatting.
  `;
  
  const structuringResponse = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "user",
          content: structuringPrompt,
        },
      ],
      temperature: 0.1,
    }),
  });
  
  if (!structuringResponse.ok) {
    throw new Error("Failed to structure analysis results");
  }
  
  const structuringResult = await structuringResponse.json();
  const jsonText = structuringResult.choices[0].message.content;
  
  // Extract the JSON object from the response
  try {
    // Remove any markdown code block formatting if present
    const cleanedJson = jsonText.replace(/```json\n?|\n?```/g, "").trim();
    return JSON.parse(cleanedJson);
  } catch (error) {
    console.error("Error parsing structured data:", error);
    console.error("Raw JSON text:", jsonText);
    throw new Error("Failed to parse structured analysis results");
  }
}
