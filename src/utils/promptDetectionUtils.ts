
// Utility functions for detecting hardcoded prompts in various programming languages

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

// Check if a string contains prompt-like content
export const isLikelyPrompt = (content: string): boolean => {
  if (!content || content.length < 20) return false;
  
  const lowerContent = content.toLowerCase();
  return PROMPT_KEYWORDS.some(keyword => lowerContent.includes(keyword.toLowerCase()));
};

// Extract potential prompts from code using regex
export const extractPromptsFromCode = (code: string, filePath: string): any[] => {
  const results: any[] = [];
  const lineCount = code.split('\n');
  
  // Function to process regex matches
  const processMatches = (regex: RegExp, promptGroupIndex: number) => {
    let match;
    while ((match = regex.exec(code)) !== null) {
      const promptContent = match[promptGroupIndex];
      
      // Only consider strings that are likely to be prompts
      if (isLikelyPrompt(promptContent)) {
        // Calculate line number by counting newlines before the match
        const upToMatch = code.substring(0, match.index);
        const lineNumber = upToMatch.split('\n').length;
        
        // Get a snippet with context (up to 3 lines before and after)
        const startLine = Math.max(0, lineNumber - 3);
        const endLine = Math.min(lineCount.length, lineNumber + 3);
        const snippet = lineCount.slice(startLine, endLine).join('\n');
        
        results.push({
          id: `${filePath}-${lineNumber}-${results.length}`,
          file: filePath,
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
  
  return results;
};

// Helper function to determine if a file should be analyzed for prompts
export const shouldAnalyzeFile = (filePath: string): boolean => {
  const supportedExtensions = ['.py', '.js', '.ts', '.tsx', '.jsx'];
  const extension = filePath.substring(filePath.lastIndexOf('.'));
  return supportedExtensions.includes(extension);
};

// Create a security risk for hardcoded system prompts
export const createSystemPromptRisk = (promptReferences: any[]): any => {
  if (promptReferences.length === 0) return null;
  
  return {
    risk: "Hardcoded System Prompts",
    severity: "Medium",
    description: "Hardcoded system prompts were detected in the codebase. These may leak sensitive information about the application logic or create security vulnerabilities through prompt injection attacks.",
    related_code_references: promptReferences.map(ref => ref.id),
    owasp_category: {
      id: "LLM07:2025",
      name: "System Prompt Leakage",
      description: "The exposure of system-level prompts that can reveal internal configurations or logic."
    }
  };
};
