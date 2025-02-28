
// Follow Deno's ES modules approach
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.7.1';

// Define cors headers for browser requests
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Helper function to check if a string is a valid GitHub URL
function isValidGitHubUrl(url) {
  if (!url || typeof url !== 'string') return false;
  // Simple regex to validate GitHub repository URLs
  return /^https?:\/\/github\.com\/[^\/]+\/[^\/]+/.test(url);
}

// Regular expressions for detecting system prompts in code
const SYSTEM_PROMPT_PATTERNS = [
  // Direct assignments to variables named like system prompts
  /(?:const|let|var)\s+(?:SYSTEM_PROMPT|systemPrompt|system_prompt|PROMPT|prompt)\s*=\s*["'`](.+?)["'`]/gs,
  
  // OpenAI API calls with system messages
  /messages\s*=\s*\[\s*\{\s*["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*["'](.+?)["']/gs,
  /messages\s*:\s*\[\s*\{\s*["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*["'](.+?)["']/gs,
  
  // Common pattern with array of messages
  /\[\s*\{\s*["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*["'](.+?)["']/gs,
  
  // Python format with triple quotes
  /SYSTEM_PROMPT\s*=\s*["']{3}([\s\S]+?)["']{3}/gs,
  
  // LangChain system message templates
  /SystemMessagePromptTemplate\.from_template\(["'`](.+?)["'`]\)/gs,
  
  // HuggingFace pipeline with system prompt
  /pipeline\(\s*[^)]*\s*system_prompt\s*=\s*["'`](.+?)["'`]/gs
];

// Main function to analyze GitHub repositories
serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse the request body
    const requestData = await req.json();
    
    // Validate repository URL
    const { repositoryUrl, apiKey, options, debugMode } = requestData;
    
    console.log(`Processing repository: ${repositoryUrl}\n`);
    
    if (!repositoryUrl) {
      throw new Error("Repository URL is required");
    }
    
    if (!isValidGitHubUrl(repositoryUrl)) {
      throw new Error("Invalid GitHub repository URL format");
    }

    if (!apiKey) {
      throw new Error("OpenAI API key is required");
    }
    
    // Construct the GitHub API URL for the repository
    const repoUrlParts = repositoryUrl.replace(/\/$/, '').split('/');
    const owner = repoUrlParts[repoUrlParts.length - 2];
    const repo = repoUrlParts[repoUrlParts.length - 1];
    
    // Repository API URL
    const githubApiUrl = `https://api.github.com/repos/${owner}/${repo}`;
    
    // Start collecting debug information
    const debugInfo = debugMode ? {
      owner,
      repo,
      api_url: githubApiUrl,
      analysis_timestamps: {},
      rate_limit_info: null,
      file_count: 0,
      extensions_found: {},
      ai_libraries_found: [],
      errors: [],
    } : null;
    
    // Fetch repository metadata
    const repoResponse = await fetch(githubApiUrl, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'RiskRover-Analysis-Tool',
      }
    });
    
    if (!repoResponse.ok) {
      if (repoResponse.status === 404) {
        throw new Error("Repository not found. It may be private or doesn't exist.");
      } else if (repoResponse.status === 403) {
        const resetTime = repoResponse.headers.get('X-RateLimit-Reset');
        const resetDate = resetTime ? new Date(parseInt(resetTime) * 1000).toLocaleString() : 'unknown time';
        throw new Error(`GitHub API rate limit exceeded. Resets at ${resetDate}`);
      } else {
        throw new Error(`GitHub API error: ${repoResponse.status} ${repoResponse.statusText}`);
      }
    }
    
    const repoData = await repoResponse.json();
    
    if (debugInfo) {
      debugInfo.repo_info = {
        name: repoData.name,
        description: repoData.description,
        default_branch: repoData.default_branch,
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
        size: repoData.size,
        created_at: repoData.created_at,
        updated_at: repoData.updated_at,
      };
      debugInfo.analysis_timestamps.start = new Date().toISOString();
    }
    
    // Get repository contents recursively
    const allFiles = await fetchAllRepoContents(owner, repo, repoData.default_branch);
    
    if (debugInfo) {
      debugInfo.file_count = allFiles.length;
      // Count file extensions
      allFiles.forEach(file => {
        const extension = file.name.split('.').pop() || 'no-extension';
        debugInfo.extensions_found[extension] = (debugInfo.extensions_found[extension] || 0) + 1;
      });
    }
    
    // Start collecting repository data
    const codeFiles = allFiles.filter(file => 
      file.type === 'file' && 
      !file.path.includes('node_modules/') && 
      !file.path.includes('venv/') &&
      !file.path.includes('.git/')
    );
    
    // Analyze code files content (batch processing to avoid rate limits)
    const codeReferences = [];
    const batchSize = 5;
    
    for (let i = 0; i < codeFiles.length; i += batchSize) {
      const batch = codeFiles.slice(i, i + batchSize);
      const batchPromises = batch.map(async (file) => {
        try {
          // Download file content
          const fileUrl = file.download_url;
          if (!fileUrl) return null; // Skip if no download URL
            
          const fileResponse = await fetch(fileUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3.raw',
              'User-Agent': 'RiskRover-Analysis-Tool',
            }
          });
            
          if (!fileResponse.ok) {
            if (debugInfo) {
              debugInfo.errors.push(`Failed to fetch ${file.path}: ${fileResponse.status}`);
            }
            return null;
          }
            
          const content = await fileResponse.text();
          
          // Process the file content for both AI libraries and system prompts
          const fileReferences = [];
  
          // Check for system prompts in the content
          let promptMatches = findSystemPrompts(content, file.path);
          if (promptMatches.length > 0) {
            fileReferences.push(...promptMatches);
          }
  
          // Only return if we have references
          if (fileReferences.length > 0) {
            return {
              file: file.path,
              content: content.length > 500 ? content.substring(0, 500) + '...' : content,
              references: fileReferences
            };
          }
          
          // If no matching patterns, return basic file info for further analysis
          return {
            file: file.path,
            content: content.length > 500 ? content.substring(0, 500) + '...' : content,
            references: []
          };
  
        } catch (error) {
          if (debugInfo) {
            debugInfo.errors.push(`Error processing ${file.path}: ${error.message}`);
          }
          console.error(`Error processing ${file.path}:`, error);
          return null;
        }
      });
        
      const batchResults = await Promise.all(batchPromises);
      codeReferences.push(...batchResults.filter(Boolean));
        
      // Slight delay to avoid hitting rate limits
      if (i + batchSize < codeFiles.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    // Extract file content to analyze through OpenAI
    const filesToAnalyze = codeReferences.map(ref => ({
      file: ref.file,
      content: ref.content,
      references: ref.references
    }));
    
    let analysis;
    try {
      if (debugInfo) {
        debugInfo.analysis_timestamps.openai_start = new Date().toISOString();
      }
      
      // Prepare system prompt with user's custom additions if provided
      const systemPromptBase = options?.systemPrompt || 
        `Analyze the GitHub repository and provide insights about AI components and security risks.`;
      
      // Generate repository analysis with OpenAI
      analysis = await analyzeRepositoryWithOpenAI(
        apiKey, 
        {
          repositoryUrl, 
          repoInfo: repoData, 
          files: filesToAnalyze
        },
        systemPromptBase
      );
      
      if (debugInfo) {
        debugInfo.analysis_timestamps.openai_end = new Date().toISOString();
      }
    } catch (error) {
      console.error("OpenAI analysis error:", error);
      
      if (debugInfo) {
        debugInfo.errors.push(`OpenAI analysis failed: ${error.message}`);
      }
      
      throw new Error(`Analysis failed: ${error.message}`);
    }
    
    // Combine analysis with code references
    const result = {
      repository_url: repositoryUrl,
      repository_info: {
        name: repoData.name,
        description: repoData.description,
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
      },
      ...analysis
    };
    
    // Add debug information if requested
    if (debugInfo) {
      debugInfo.analysis_timestamps.end = new Date().toISOString();
      result.debug = debugInfo;
    }
    
    return new Response(
      JSON.stringify(result),
      { 
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        } 
      }
    );
  } catch (error) {
    console.error(`Error analyzing repository:`, error);
    
    return new Response(
      JSON.stringify({ 
        error: error.message || "Unknown error occurred"
      }),
      { 
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        } 
      }
    );
  }
});

// Helper function to find system prompts in code content
function findSystemPrompts(content, filePath) {
  const matches = [];
  
  // Apply all regex patterns to find potential system prompts
  for (const pattern of SYSTEM_PROMPT_PATTERNS) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      if (match[1] && match[1].length > 10) { // Only consider non-trivial prompts
        // Extract a snippet of code around the match for context
        const startPos = Math.max(0, match.index - 50);
        const endPos = Math.min(content.length, match.index + match[0].length + 50);
        const contextCode = content.substring(startPos, endPos);
        
        matches.push({
          type: "system_prompt",
          pattern_matched: pattern.toString().replace(/^\/|\/gs$/g, ''),
          prompt_content: match[1].substring(0, 100) + (match[1].length > 100 ? '...' : ''),
          code_snippet: contextCode,
          file: filePath,
          verified: true
        });
      }
    }
  }
  
  return matches;
}

// Function to fetch all repository content recursively
async function fetchAllRepoContents(owner, repo, branch = 'main', path = '') {
  const apiUrl = path
    ? `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${branch}`
    : `https://api.github.com/repos/${owner}/${repo}/contents?ref=${branch}`;
  
  try {
    const response = await fetch(apiUrl, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'RiskRover-Analysis-Tool',
      }
    });
    
    if (!response.ok) {
      console.error(`Error fetching repo contents for ${path || 'root'}: ${response.status}`);
      return [];
    }
    
    const contents = await response.json();
    
    // If single file was returned (not array), wrap in array
    const items = Array.isArray(contents) ? contents : [contents];
    
    let allContents = [...items];
    
    // Recursively process directories
    for (const item of items) {
      if (item.type === 'dir') {
        const subContents = await fetchAllRepoContents(owner, repo, branch, item.path);
        allContents = [...allContents, ...subContents];
      }
    }
    
    return allContents;
  } catch (error) {
    console.error(`Error fetching repo contents for ${path || 'root'}:`, error);
    return [];
  }
}

// Function to analyze repository with OpenAI
async function analyzeRepositoryWithOpenAI(apiKey, repository, systemPrompt) {
  // Prepare repository data for analysis
  const { repositoryUrl, repoInfo, files } = repository;
  
  // Structured summary of the repository
  const repoSummary = `
    Repository: ${repositoryUrl}
    Name: ${repoInfo.name}
    Description: ${repoInfo.description || 'No description provided'}
    Stars: ${repoInfo.stargazers_count}
    Forks: ${repoInfo.forks_count}
    
    Files to analyze (${files.length} files):
    ${files.map(f => `- ${f.file}`).join('\n')}
    
    Code references detected in preliminary scan:
    ${files.filter(f => f.references.length > 0)
      .map(f => `- ${f.file}: ${f.references.length} references found`)
      .join('\n')}
  `;
  
  // Format file content for analysis
  const filesContent = files.map(file => {
    // If the file already has references from our preliminary scan (e.g., system prompts)
    // add them as metadata
    let referenceInfo = '';
    if (file.references && file.references.length > 0) {
      referenceInfo = '\nPreliminary scan found the following references:\n' + 
        file.references.map(ref => 
          `- Type: ${ref.type}\n  Content: ${ref.prompt_content || ref.content || 'N/A'}`
        ).join('\n');
    }
    
    return `
      File: ${file.file}${referenceInfo}
      Content:
      \`\`\`
      ${file.content}
      \`\`\`
    `;
  }).join('\n\n---\n\n');
  
  // Combine all data for analysis
  const analysisPrompt = `
    ${repoSummary}
    
    Detailed file contents:
    ${filesContent}
  `;
  
  // Structure for AI components detection
  const aiComponentsStructure = `
    Please structure your response as a JSON object with the following format:
    {
      "confidence_score": number between 0-100 representing confidence in analysis,
      "ai_components_detected": [
        {
          "component_type": "string (e.g., 'LLM Integration', 'Vector Database', 'Embedding Generation')",
          "component_name": "string (e.g., 'OpenAI', 'LangChain', 'FAISS')",
          "description": "string explaining the component",
          "risk_level": "string (Low, Medium, High)",
          "files": ["array of file paths where component is used"]
        }
      ],
      "security_risks": [
        {
          "risk_type": "string (e.g., 'API Key Leakage', 'System Prompt Leakage')",
          "description": "string explaining the risk",
          "severity": "string (Low, Medium, High, Critical)",
          "location": "string (file path or general)",
          "recommendation": "string with remediation advice"
        }
      ],
      "code_references": [
        {
          "file": "string (file path)",
          "content": "string (relevant code snippet)",
          "description": "string explaining what was found",
          "verified": boolean (whether this reference was actually confirmed in the code)
        }
      ],
      "remediation_suggestions": [
        "string with specific remediation advice"
      ]
    }
  `;
  
  // Call OpenAI API for analysis
  const openaiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: `${systemPrompt}
          
          You are performing a security and AI component analysis of a GitHub repository.
          ${aiComponentsStructure}`
        },
        {
          role: "user",
          content: analysisPrompt
        }
      ],
      temperature: 0.1,
    })
  });
  
  if (!openaiResponse.ok) {
    const errorData = await openaiResponse.json();
    throw new Error(`OpenAI API error: ${errorData.error?.message || openaiResponse.statusText}`);
  }
  
  const response = await openaiResponse.json();
  
  try {
    // Extract and parse the JSON from the response
    const content = response.choices[0].message.content;
    
    // Find JSON content (sometimes OpenAI wraps it in markdown code blocks)
    let jsonMatch = content.match(/```json\n([\s\S]*?)\n```/) || 
                    content.match(/```\n([\s\S]*?)\n```/) ||
                    [null, content];
    
    const jsonContent = jsonMatch[1] || content;
    const parsedResult = JSON.parse(jsonContent);
    
    // Add hardcoded system prompt findings from our preliminary scan to the security risks
    const systemPromptFindings = files
      .flatMap(file => file.references)
      .filter(ref => ref.type === "system_prompt");
    
    if (systemPromptFindings.length > 0 && !parsedResult.security_risks.some(risk => risk.risk_type === "System Prompt Leakage")) {
      parsedResult.security_risks.push({
        risk_type: "System Prompt Leakage",
        description: "Hardcoded system prompts found in the codebase. These can leak information about your AI system's behavior and potentially be manipulated.",
        severity: "High",
        location: systemPromptFindings.map(f => f.file).join(", "),
        recommendation: "Move system prompts to environment variables or configuration files that are not committed to the repository."
      });
      
      // Also add these to code references
      systemPromptFindings.forEach(finding => {
        if (!parsedResult.code_references.some(ref => ref.file === finding.file && ref.content === finding.code_snippet)) {
          parsedResult.code_references.push({
            file: finding.file,
            content: finding.code_snippet,
            description: "Contains hardcoded system prompt: " + finding.prompt_content,
            verified: true
          });
        }
      });
    }
    
    return parsedResult;
  } catch (error) {
    console.error("Error parsing OpenAI response:", error);
    console.error("Response content:", response.choices[0].message.content);
    throw new Error("Failed to parse analysis results from OpenAI");
  }
}
