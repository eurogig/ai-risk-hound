import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.36.0';
import "https://deno.land/x/xhr@0.1.0/mod.ts"; // Required for OpenAI API to work
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// CORS Headers for allowing frontend access to this function
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Initialize Supabase client
const supabaseClient = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
);

// Serve the HTTP request
serve(async (req) => {
  console.log(`Starting repository analysis...`);

  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    // Get request data
    const { repositoryUrl, apiKey, options, debugMode } = await req.json();
    
    // Validate required parameters
    if (!repositoryUrl) {
      throw new Error('Repository URL is required');
    }
    
    if (!apiKey) {
      throw new Error('OpenAI API key is required');
    }

    // Validate GitHub URL format
    const isValidGithubUrl = /https?:\/\/github\.com\/[^\/]+\/[^\/]+/.test(repositoryUrl);
    if (!isValidGithubUrl) {
      throw new Error('Invalid GitHub repository URL');
    }

    console.log(`Repository URL validated: ${repositoryUrl}`);
    
    // Extract repository info from URL
    const urlMatch = repositoryUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    if (!urlMatch) {
      throw new Error('Failed to parse GitHub repository URL');
    }
    
    const owner = urlMatch[1];
    let repo = urlMatch[2];
    
    // Remove .git suffix if present
    if (repo.endsWith('.git')) {
      repo = repo.slice(0, -4);
    }

    // Extract branch from URL if present, otherwise default to main/master
    let branch = "main"; // Default to main
    const branchMatch = repositoryUrl.match(/\/tree\/([^\/]+)/);
    if (branchMatch) {
      branch = branchMatch[1];
    }

    const repositoryData = await fetchRepositoryData(owner, repo, branch);
    
    console.log(`Successfully fetched repository data for ${owner}/${repo}`);
    
    let debug = {};
    if (debugMode) {
      debug = {
        repo_data: {
          owner,
          repo,
          branch,
          file_count: repositoryData.length
        }
      };
    }
    
    // Add hardcoded system prompt detection
    const { promptResults, promptRisk } = detectSystemPrompts(repositoryData);
    if (promptResults.length > 0) {
      console.log(`Detected ${promptResults.length} potential hardcoded system prompts`);
      if (debugMode) {
        debug = {
          ...debug,
          prompt_detection: {
            count: promptResults.length,
            files: promptResults.map(r => r.file)
          }
        };
      }
    }

    // Process repository content
    const prompt = buildPrompt(repositoryData, options?.systemPrompt);
    const response = await analyzeWithOpenAI(prompt, apiKey);
    
    // New: Check for and remove markdown formatting in the response
    let jsonStr = response;
    
    // Check if the response contains markdown code blocks
    if (jsonStr.includes('```json')) {
      console.log('Detected markdown JSON formatting in OpenAI response, cleaning...');
      // Extract JSON from markdown code blocks
      const jsonMatch = jsonStr.match(/```json\s*([\s\S]*?)\s*```/);
      if (jsonMatch && jsonMatch[1]) {
        jsonStr = jsonMatch[1].trim();
      }
    }
    
    // Parse the response into a structured report
    let report;
    try {
      report = JSON.parse(jsonStr);
    } catch (parseError) {
      console.error('Error parsing OpenAI response:', parseError);
      console.error('Response content that failed to parse:', jsonStr.substring(0, 500) + '...');
      throw new Error('Failed to parse AI analysis. The response was not valid JSON.');
    }
    
    // Add the hardcoded system prompt risk to the report if found
    if (promptRisk && promptResults.length > 0) {
      // Check if there's already a system prompt risk in the report
      const existingPromptRisk = report.security_risks?.find(risk => 
        risk.risk?.toLowerCase().includes('system prompt') || 
        risk.risk?.toLowerCase().includes('prompt leakage')
      );
      
      if (existingPromptRisk) {
        // Merge the detected prompt references with the existing risk
        existingPromptRisk.related_code_references = [
          ...(existingPromptRisk.related_code_references || []),
          ...promptRisk.related_code_references
        ];
      } else {
        // Add the new risk to the report
        report.security_risks = report.security_risks || [];
        report.security_risks.push(promptRisk);
      }
      
      // Add the prompt references to the code references
      report.code_references = report.code_references || [];
      report.code_references.push(...promptResults);
    }
    
    // Return the analysis result
    return new Response(
      JSON.stringify({
        ...report,
        debug: debugMode ? debug : undefined
      }),
      { 
        headers: { 
          ...corsHeaders,
          'Content-Type': 'application/json'
        } 
      }
    );
  } catch (error) {
    console.error('Error in analyze-repository function:', error);
    
    return new Response(
      JSON.stringify({ 
        error: error.message || 'Failed to analyze repository'
      }),
      { 
        status: 400,
        headers: { 
          ...corsHeaders,
          'Content-Type': 'application/json'
        } 
      }
    );
  }
});

// The helper functions:
// These are the core functions that do the actual work

// Function to download repository contents
async function fetchRepositoryData(owner: string, repo: string, branch: string) {
  console.log(`Fetching repository data for ${owner}/${repo}:${branch}`);
  
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const response = await fetch(apiUrl, {
    headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'RiskRover-Analyzer'
    }
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`GitHub API error: ${response.status} ${errorText}`);
    throw new Error(`Failed to fetch repository data: ${response.status} ${response.statusText}`);
  }
  
  const data = await response.json();
  if (!data.tree) {
    throw new Error('Repository structure not found');
  }
  
  const fileData = [];
  
  // Filter to only include relevant files
  const relevantFiles = data.tree.filter((item: any) => {
    return item.type === 'blob' && shouldAnalyzeFile(item.path);
  });
  
  console.log(`Found ${relevantFiles.length} relevant files to analyze`);
  
  // Limit the number of files to download to avoid overloading
  const filesToDownload = relevantFiles.slice(0, 50);
  
  // Download all relevant files in parallel
  const fileDownloadPromises = filesToDownload.map(async (file: any) => {
    try {
      const fileContent = await fetchFileContent(owner, repo, file.path, branch);
      return {
        path: file.path,
        content: fileContent,
      };
    } catch (error) {
      console.warn(`Failed to download ${file.path}: ${error.message}`);
      return null;
    }
  });
  
  const downloadedFiles = await Promise.all(fileDownloadPromises);
  
  // Filter out any failed downloads
  return downloadedFiles.filter(file => file !== null);
}

// Helper function to download individual files
async function fetchFileContent(owner: string, repo: string, path: string, branch: string) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch file content: ${response.status}`);
  }
  
  return await response.text();
}

// Function to build the analysis prompt
function buildPrompt(repositoryData: any[], systemPrompt?: string) {
  let filesContent = '';
  
  // Add repository structure
  filesContent += "Repository Structure:\n";
  filesContent += repositoryData.map(file => `- ${file.path}`).join('\n');
  filesContent += '\n\n';
  
  // Add file contents (limited to keep prompt within token limits)
  let totalTokenCount = 0;
  const estimatedTokensPerChar = 0.25; // Rough estimate of tokens per character
  const maxTokens = 60000; // Maximum tokens to allow in the prompt
  
  for (const file of repositoryData) {
    const estimatedTokens = file.content.length * estimatedTokensPerChar;
    
    // Skip this file if adding it would exceed the token limit
    if (totalTokenCount + estimatedTokens > maxTokens) {
      filesContent += `Note: Some files were omitted to keep within the token limit.\n`;
      break;
    }
    
    filesContent += `File: ${file.path}\n`;
    filesContent += '```\n';
    filesContent += file.content.slice(0, 25000); // Limit each file to 25000 chars
    
    if (file.content.length > 25000) {
      filesContent += '\n... (file truncated for brevity) ...';
    }
    
    filesContent += '\n```\n\n';
    
    totalTokenCount += estimatedTokens;
  }
  
  // Default system prompt if none provided
  const defaultSystemPrompt = `Analyze the GitHub repository and provide insights about AI components and security risks. 
  
  When analyzing repositories:
  1. Only report code references that you can confirm exist in the repository. 
  2. Do not invent or hallucinate file paths or code snippets.
  3. If uncertain about specific files, focus on identifying patterns and general concerns instead.
  4. If you cannot find specific code references, leave that section empty rather than making suggestions.
  
  IMPORTANT: Look carefully for HARDCODED SYSTEM PROMPTS in Python, TypeScript, and JavaScript files.
  - Check for string assignments like SYSTEM_PROMPT = "You are an AI assistant..."
  - Check for hardcoded function arguments like messages=[{"role": "system", "content": "You are helpful."}]
  - These are security risks because they can leak information or be manipulated
  - Report them under "System Prompt Leakage" risk category
  
  Be thorough in your analysis of all AI components and any security issues that may exist.`;
  
  const finalSystemPrompt = systemPrompt || defaultSystemPrompt;
  
  const prompt = {
    model: "gpt-4-turbo-preview",
    messages: [
      {
        role: "system",
        content: finalSystemPrompt
      },
      {
        role: "user",
        content: `Here's the repository content I'd like you to analyze:\n\n${filesContent}\n\nPlease provide a complete analysis focusing on AI components and security risks, looking especially for hardcoded system prompts. Return your analysis in a structured JSON format with the following fields:
        
        {
          "confidence_score": number between 0 and 1 representing how confident you are this is an AI repository,
          "ai_components_detected": [array of objects with name, type, description, libraries_used, feature_function, and key_implementation_details],
          "security_risks": [array of objects with risk name, severity, description, and related_code_references],
          "code_references": [array of objects with id, file, line, snippet, and verified flag],
          "remediation_suggestions": [array of objects with category, type and description]
        }
        
        Begin your response ONLY with the JSON object, without any intro text. Make sure the JSON is valid and properly formatted.`
      }
    ],
    temperature: 0.0,
    max_tokens: 4096
  };
  
  return prompt;
}

// Function to send the analysis to OpenAI
async function analyzeWithOpenAI(prompt: any, apiKey: string) {
  console.log('Sending analysis request to OpenAI');
  
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify(prompt)
  });
  
  if (!response.ok) {
    const errorData = await response.text();
    console.error('OpenAI API error:', errorData);
    throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
  }
  
  const data = await response.json();
  return data.choices[0].message.content;
}

// Helper function to detect hardcoded system prompts
function detectSystemPrompts(repositoryData: any[]) {
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

  // Function to check if a string contains prompt-like content
  const isLikelyPrompt = (content: string): boolean => {
    if (!content || content.length < 20) return false;
    
    const lowerContent = content.toLowerCase();
    return PROMPT_KEYWORDS.some(keyword => lowerContent.includes(keyword.toLowerCase()));
  };

  const promptResults = [];
  
  // Process each file in the repository
  for (const file of repositoryData) {
    if (!shouldAnalyzeFile(file.path)) continue;
    
    const content = file.content;
    const lineCount = content.split('\n');
    
    // Function to process regex matches
    const processMatches = (regex: RegExp, promptGroupIndex: number) => {
      let match;
      while ((match = regex.exec(content)) !== null) {
        const promptContent = match[promptGroupIndex];
        
        // Only consider strings that are likely to be prompts
        if (isLikelyPrompt(promptContent)) {
          // Calculate line number by counting newlines before the match
          const upToMatch = content.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length;
          
          // Get a snippet with context (up to 3 lines before and after)
          const startLine = Math.max(0, lineNumber - 3);
          const endLine = Math.min(lineCount.length, lineNumber + 3);
          const snippet = lineCount.slice(startLine, endLine).join('\n');
          
          promptResults.push({
            id: `${file.path}-${lineNumber}-${promptResults.length}`,
            file: file.path,
            line: lineNumber,
            prompt: promptContent.substring(0, 150) + (promptContent.length > 150 ? '...' : ''),
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
  }
  
  // Create a security risk object if prompts were found
  const promptRisk = promptResults.length > 0 ? {
    risk: "Hardcoded System Prompts",
    severity: "Medium",
    description: "Hardcoded system prompts were detected in the codebase. These may leak sensitive information about the application logic or create security vulnerabilities through prompt injection attacks.",
    related_code_references: promptResults.map(ref => ref.id),
    owasp_category: {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    }
  } : null;
  
  return { promptResults, promptRisk };
}

// Helper function to determine if a file should be analyzed
function shouldAnalyzeFile(filePath: string): boolean {
  // Check file extensions for code files that might contain system prompts
  const codeExtensions = ['.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb'];
  
  // Get the file extension
  const lastDotIndex = filePath.lastIndexOf('.');
  if (lastDotIndex === -1) return false;
  
  const extension = filePath.slice(lastDotIndex);
  return codeExtensions.includes(extension);
}
