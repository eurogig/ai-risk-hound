
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

    // Enhanced repository scraping logic to handle nested structures
    const repositoryContent = await fetchRepositoryContent(repositoryUrl);
    
    if (repositoryContent.error) {
      return new Response(
        JSON.stringify({ error: repositoryContent.error }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
      );
    }

    // Debug mode - include repository content in response if requested
    const debugMode = options.debugMode || false;
    let debugInfo = null;
    
    if (debugMode) {
      // Limit debug info to avoid huge responses
      debugInfo = {
        fileCount: repositoryContent.files.length,
        filePaths: repositoryContent.files.map(f => f.path).slice(0, 100), // Just send first 100 paths for debugging
        totalFilesFound: repositoryContent.files.length,
        repositoryName: repositoryContent.repositoryName,
        repoSize: JSON.stringify(repositoryContent).length,
      };
      console.log(`Debug info: ${JSON.stringify(debugInfo, null, 2)}`);
    }

    // Analyze the repository using OpenAI
    const analysisResult = await analyzeRepository(repositoryContent, options);

    // Return the result
    return new Response(
      JSON.stringify({ ...analysisResult, debug: debugInfo }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Error processing request:', error);
    
    return new Response(
      JSON.stringify({ error: error.message }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
    );
  }
})

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

  // Call OpenAI API
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${openaiApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: "gpt-4",
      messages: messages,
      temperature: 0.2,
      max_tokens: 4000,
      response_format: { type: "json_object" }
    })
  });

  if (!response.ok) {
    const errorData = await response.text();
    console.error("OpenAI API error:", errorData);
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
    // Vector databases
    { name: 'faiss', type: 'Vector Database' },
    { name: 'pinecone', type: 'Vector Database' },
    { name: 'weaviate', type: 'Vector Database' },
    { name: 'chromadb', type: 'Vector Database' },
    { name: 'qdrant', type: 'Vector Database' },
    // JavaScript
    { name: '@openai/api', type: 'LLM API' },
    { name: 'langchainjs', type: 'LLM Framework' },
    { name: '@huggingface/inference', type: 'ML API' },
    { name: 'tensorflow.js', type: 'ML Framework' },
    { name: '@tensorflow/tfjs', type: 'ML Framework' },
    { name: 'ml5.js', type: 'ML Framework' },
    { name: 'brain.js', type: 'ML Framework' },
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
    'import pandas', 'from pandas'
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
      "related_code_references": ["ref_id1", "ref_id2"]
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

For code_references, include only actual code you can verify from the provided files.`;

  return prompt;
}
