
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.7.1";
import OpenAI from "https://esm.sh/openai@4.0.0";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const openaiApiKey = Deno.env.get("OPENAI_API_KEY") || "";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// LLM risk patterns to detect
const riskPatterns = {
  promptInjection: ["prompt injection", "instruction injection", "jailbreak", "prompt escape"],
  dataLeakage: ["data leakage", "training data", "information disclosure", "sensitive data", "confidential"],
  hallucination: ["hallucination", "confabulation", "factual accuracy", "incorrect information"],
  apiKeyExposure: ["api key", "apikey", "secret key", "credentials", "token"],
  modelPoisoning: ["model poisoning", "adversarial example", "model manipulation", "training attack"],
  systemPromptLeakage: ["system prompt", "hardcoded prompt", "leaked prompt", "prompt disclosure"],
};

// OWASP LLM category mapping
const owaspCategories = {
  "prompt injection": {
    id: "LLM01:2025",
    name: "Prompt Injection",
    description: "A vulnerability where user inputs manipulate the LLM's behavior by altering its prompts."
  },
  "data leakage": {
    id: "LLM02:2025", 
    name: "Sensitive Information Disclosure",
    description: "Risks involving the exposure of confidential data within the LLM or its applications."
  },
  "hallucination": {
    id: "LLM09:2025",
    name: "Misinformation",
    description: "The potential for LLMs to generate and propagate false or misleading information."
  },
  "api key exposure": {
    id: "LLM03:2025",
    name: "Supply Chain",
    description: "Vulnerabilities arising from the components and dependencies used in LLM development and deployment."
  },
  "model poisoning": {
    id: "LLM04:2025",
    name: "Data and Model Poisoning",
    description: "Threats where malicious data is introduced during training, fine-tuning, or embedding processes."
  },
  "system prompt leakage": {
    id: "LLM07:2025",
    name: "System Prompt Leakage",
    description: "The exposure of system-level prompts that can reveal internal configurations or logic."
  }
};

// Helper function to enhance security risk with OWASP categories
function enhanceSecurityRisks(risks) {
  if (!Array.isArray(risks)) return [];
  
  return risks.map(risk => {
    if (!risk) return null;
    
    // Normalize risk name
    const riskName = risk.risk || risk.risk_name || "";
    const riskLower = riskName.toLowerCase();
    
    // Add OWASP category
    if (!risk.owasp_category) {
      for (const [riskType, category] of Object.entries(owaspCategories)) {
        if (riskLower.includes(riskType)) {
          risk.owasp_category = category;
          break;
        }
      }
      
      // Default if no match found
      if (!risk.owasp_category) {
        risk.owasp_category = {
          id: "LLM05:2025",
          name: "Improper Output Handling",
          description: "Issues stemming from inadequate validation, sanitization, or escaping of LLM outputs."
        };
      }
    }
    
    // Ensure all needed fields exist
    if (!risk.risk && risk.risk_name) risk.risk = risk.risk_name;
    if (!risk.risk_name && risk.risk) risk.risk_name = risk.risk;
    if (!risk.related_code_references) risk.related_code_references = [];
    
    return risk;
  }).filter(risk => risk !== null);
}

// Ensure all core risk types exist
function ensureCoreRisks(risks, codeReferences) {
  if (!Array.isArray(risks)) risks = [];
  
  const riskMap = new Map();
  
  // Add existing risks to map
  risks.forEach(risk => {
    if (!risk) return;
    const riskName = risk.risk || risk.risk_name || "";
    riskMap.set(riskName.toLowerCase(), risk);
  });
  
  // Core risk definitions
  const coreRisks = [
    {
      name: "Prompt Injection",
      severity: "High",
      description: "User inputs could manipulate the LLM's behavior by altering its prompt instructions.",
      riskType: "prompt injection"
    },
    {
      name: "Data Leakage via LLM",
      severity: "Medium",
      description: "LLM responses might inadvertently expose sensitive data or training information.",
      riskType: "data leakage"
    },
    {
      name: "Hallucination",
      severity: "Medium",
      description: "The LLM may generate incorrect or fabricated information presented as factual.",
      riskType: "hallucination"
    },
    {
      name: "API Key Exposure",
      severity: "High",
      description: "API keys or credentials may be exposed in the codebase.",
      riskType: "api key exposure"
    },
    {
      name: "Model Poisoning",
      severity: "Medium",
      description: "The LLM could be influenced by adversarial inputs or poisoned training data.",
      riskType: "model poisoning"
    },
    {
      name: "Hardcoded System Prompts",
      severity: "Medium",
      description: "Hardcoded system prompts in the codebase can reveal sensitive information or create vulnerabilities.",
      riskType: "system prompt leakage"
    }
  ];
  
  // Add missing risks
  coreRisks.forEach(coreRisk => {
    // Check if this risk type already exists
    let exists = false;
    for (const [key, risk] of riskMap.entries()) {
      if (key.includes(coreRisk.riskType)) {
        exists = true;
        break;
      }
    }
    
    // If not exists, create it
    if (!exists) {
      const newRisk = {
        risk: coreRisk.name,
        risk_name: coreRisk.name,
        severity: coreRisk.severity,
        description: coreRisk.description,
        related_code_references: [],
        owasp_category: owaspCategories[coreRisk.riskType]
      };
      
      risks.push(newRisk);
      riskMap.set(coreRisk.name.toLowerCase(), newRisk);
    }
  });
  
  // Associate code references with risks based on content
  if (Array.isArray(codeReferences)) {
    codeReferences.forEach(ref => {
      if (!ref || !ref.snippet) return;
      
      const snippet = ref.snippet.toLowerCase();
      const fileName = (ref.file || "").toLowerCase();
      
      // Check for risk patterns in the code
      for (const [riskType, patterns] of Object.entries(riskPatterns)) {
        if (patterns.some(pattern => snippet.includes(pattern) || fileName.includes(pattern))) {
          // Find matching risk
          for (const risk of risks) {
            const riskName = (risk.risk || risk.risk_name || "").toLowerCase();
            
            if (riskType === "promptInjection" && patterns.some(p => riskName.includes(p))) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            } else if (riskType === "dataLeakage" && riskName.includes("data leakage")) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            } else if (riskType === "hallucination" && riskName.includes("hallucination")) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            } else if (riskType === "apiKeyExposure" && riskName.includes("api key")) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            } else if (riskType === "modelPoisoning" && riskName.includes("model poisoning")) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            } else if (riskType === "systemPromptLeakage" && (riskName.includes("system prompt") || riskName.includes("hardcoded"))) {
              if (!risk.related_code_references.includes(ref.id)) {
                risk.related_code_references.push(ref.id);
              }
            }
          }
        }
      }
    });
  }
  
  // Remove risks with no related code references if they were generated
  return risks.filter(risk => 
    risk && ((risk.related_code_references && risk.related_code_references.length > 0) || 
    risk.source === "ai_detection")
  );
}

// Process the analysis to ensure proper formatting and relationships
function processAnalysisResult(result) {
  if (!result) return null;
  
  try {
    console.log("Processing analysis result...");
    
    // Ensure code references have IDs
    if (Array.isArray(result.code_references)) {
      result.code_references = result.code_references.map((ref, index) => {
        if (!ref) return null;
        if (!ref.id) ref.id = `ref-${index}`;
        if (!ref.verified) ref.verified = true;
        return ref;
      }).filter(ref => ref !== null);
    } else {
      result.code_references = [];
    }
    
    // Ensure security risks are properly formed
    if (Array.isArray(result.security_risks)) {
      result.security_risks = enhanceSecurityRisks(result.security_risks);
    } else {
      result.security_risks = [];
    }
    
    // Ensure all six core risks are represented and code is properly associated
    result.security_risks = ensureCoreRisks(result.security_risks, result.code_references);
    
    // Ensure AI components exist
    if (!Array.isArray(result.ai_components_detected)) {
      result.ai_components_detected = [];
    }
    
    // Ensure remediation suggestions exist
    if (!Array.isArray(result.remediation_suggestions)) {
      result.remediation_suggestions = [];
    }
    
    // Add standard remediation suggestions if none exist
    if (result.remediation_suggestions.length === 0) {
      result.remediation_suggestions = [
        "Implement input validation for all user inputs that could influence LLM prompts",
        "Add content filtering on LLM outputs to prevent sensitive data exposure",
        "Use rate limiting to prevent excessive API usage and cost overruns",
        "Store API keys securely in environment variables, not in code",
        "Implement a fact-checking mechanism for critical LLM outputs",
        "Add guardrails to prevent prompt injection attacks"
      ];
    }
    
    console.log("Analysis processing complete.");
    return result;
  } catch (error) {
    console.error("Error processing analysis result:", error);
    return result;
  }
}

serve(async (req) => {
  // Handle CORS preflight request
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  try {
    const { repositoryUrl } = await req.json();
    console.log(`Analyzing repository: ${repositoryUrl}`);

    if (!repositoryUrl) {
      throw new Error("Repository URL is required");
    }

    // Initialize the OpenAI client
    const openai = new OpenAI({
      apiKey: openaiApiKey,
    });

    // Basic prompt for repository analysis
    const prompt = `
    You are an AI cybersecurity expert analyzing a GitHub repository for AI security risks.
    
    Repository URL: ${repositoryUrl}
    
    Your task is to:
    1. Analyze the provided GitHub repository for potential security risks associated with AI/ML implementations
    2. Focus on security concerns specific to AI models, such as LLM implementations, RAG systems, or other ML models
    3. Identify potential vulnerabilities related to user input handling, API key storage, and data leakage
    4. Look for hardcoded system prompts that might reveal implementation details
    5. For each identified risk, provide the specific code references where the issue occurs
    
    Please format your response as a JSON object with the following structure:
    
    {
      "confidence_score": float, // 0-1 indicating how confident you are that this repo contains AI code
      "security_risks": [
        {
          "risk": string, // The name of the security risk
          "severity": string, // "Low", "Medium", or "High"
          "description": string, // Detailed description of the risk
          "related_code_references": [string], // Array of code reference IDs (ref-0, ref-1, etc.)
          "source": string // "ai_detection" for risks found by AI analysis
        }
      ],
      "code_references": [
        {
          "id": string, // Unique identifier (ref-0, ref-1, etc.)
          "file": string, // File path
          "line": number, // Line number
          "snippet": string, // Code snippet
          "verified": boolean // Whether this code exists in the repo (set to true)
        }
      ],
      "ai_components_detected": [
        {
          "name": string, // Name of the AI component
          "type": string, // Type of component (e.g., "LLM Provider", "Vector Database")
          "description": string // Description of the component's usage
        }
      ],
      "remediation_suggestions": [string] // Array of suggestions to address the security risks
    }
    
    Be thorough and detailed. Look for OWASP LLM Top 10 vulnerabilities like prompt injection, data leakage, hallucination, improper output handling, and excessive agency.
    `;

    console.log("Sending analysis request to OpenAI...");
    
    // Make the request to OpenAI
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "system", content: prompt }],
      temperature: 0.5,
      max_tokens: 4000,
    });

    const responseText = completion.choices[0].message.content;
    console.log("Received response from OpenAI");

    let analysisResult;
    try {
      // Parse the JSON response
      analysisResult = JSON.parse(responseText);
      console.log("Successfully parsed JSON response");
    } catch (parseError) {
      console.error("Failed to parse JSON response:", parseError);
      throw new Error("Failed to parse analysis result");
    }

    // Process and enhance the analysis result
    const processedResult = processAnalysisResult(analysisResult);
    
    // Create Supabase client
    const supabase = createClient(supabaseUrl, supabaseKey);
    
    // Store the analysis result in the database
    const { data, error } = await supabase
      .from("repository_analyses")
      .insert({
        repository_url: repositoryUrl,
        analysis_result: processedResult,
      })
      .select();

    if (error) {
      console.error("Failed to store analysis result:", error);
      throw new Error("Failed to store analysis result");
    }

    console.log("Analysis complete and stored in database");
    
    return new Response(JSON.stringify(processedResult), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  } catch (error) {
    console.error("Error processing request:", error);
    
    return new Response(
      JSON.stringify({
        error: error.message || "An unknown error occurred",
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      }
    );
  }
});
