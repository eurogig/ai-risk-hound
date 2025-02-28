
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// CORS headers for cross-origin requests
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

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
    
    // For simplicity, we'll return mock data
    const mockAnalysisResult = {
      ai_components_detected: [
        {
          name: "OpenAI API",
          type: "LLM API",
          confidence: 0.95
        },
        {
          name: "Langchain",
          type: "AI Framework",
          confidence: 0.85
        }
      ],
      security_risks: [
        {
          risk: "API Key Exposure",
          severity: "Critical",
          description: "API key found hardcoded in source files"
        },
        {
          risk: "Potential for Prompt Injection",
          severity: "High",
          description: "User input is passed directly to AI model without sanitization"
        },
        {
          risk: "Data Privacy Concerns",
          severity: "Medium",
          description: "Sensitive user data might be sent to external AI services"
        }
      ],
      code_references: [
        {
          file: "src/utils/api.js",
          line: 15,
          snippet: "const OPENAI_API_KEY = 'sk-...';"
        },
        {
          file: "src/components/ChatBox.jsx",
          line: 42,
          snippet: "const response = await openai.chat.completions.create({ messages: [userInput] });"
        }
      ],
      confidence_score: 0.87,
      remediation_suggestions: [
        "Use environment variables for API keys instead of hardcoding them",
        "Implement input validation before passing to LLM",
        "Set up content filtering for LLM inputs and outputs",
        "Use parameterized prompts instead of direct string concatenation",
        "Implement rate limiting for API requests"
      ]
    };
    
    // Return the mock analysis result
    return new Response(
      JSON.stringify(mockAnalysisResult),
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
