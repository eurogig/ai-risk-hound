
// Import from npm: URL instead of using a relative import
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.21.0';
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Type definitions for the response
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

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse request body
    const reqData = await req.json();
    const repositoryUrl = reqData.repositoryUrl;
    
    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: "Repository URL is required" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 400 }
      );
    }

    console.log(`Analyzing repository: ${repositoryUrl}`);
    
    // In a real implementation, you'd fetch and analyze the repository code here
    // For this example, we'll return mock data with explicit relationships
    
    // Generate mock code references with unique IDs
    const codeReferences = [
      {
        id: "ref-1",
        file: "src/components/UserAuth.js",
        line: 42,
        snippet: "const userToken = localStorage.getItem('auth_token');",
        verified: true,
      },
      {
        id: "ref-2",
        file: "src/utils/api.js",
        line: 17,
        snippet: "axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;",
        verified: true,
      },
      {
        id: "ref-3",
        file: "src/pages/Dashboard.js",
        line: 86,
        snippet: "const response = await fetch(API_URL + '/user/data', { credentials: 'include' });",
        verified: true,
      },
      {
        id: "ref-4",
        file: "src/components/AIChat.js",
        line: 12,
        snippet: "import { OpenAI } from 'openai';",
        verified: true,
      },
      {
        id: "ref-5",
        file: "src/components/AIChat.js",
        line: 24,
        snippet: "const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });",
        verified: true,
      }
    ];
    
    // Security risks with explicit references to code
    const securityRisks = [
      {
        risk: "Insecure Token Storage",
        severity: "High",
        description: "Authentication tokens stored in localStorage can be accessed by XSS attacks.",
        related_code_references: ["ref-1"]
      },
      {
        risk: "Hard-coded API Keys",
        severity: "Critical",
        description: "API keys should not be hard-coded in the application, especially for AI services.",
        related_code_references: ["ref-5"]
      },
      {
        risk: "Insecure API Communication",
        severity: "Medium",
        description: "API requests should use HTTPS and proper authentication methods.",
        related_code_references: ["ref-2", "ref-3"]
      }
    ];
    
    // Now update code references with their related risks (bidirectional relationship)
    const enhancedCodeReferences = codeReferences.map(ref => {
      const relatedRisks = securityRisks
        .filter(risk => risk.related_code_references.includes(ref.id))
        .map(risk => risk.risk);
      
      return {
        ...ref,
        relatedRisks: relatedRisks.length > 0 ? relatedRisks : undefined
      };
    });
    
    // Prepare the complete analysis
    const analysis: RepositoryAnalysis = {
      ai_components_detected: [
        {
          name: "OpenAI Integration",
          type: "API Client",
          confidence: 0.95
        },
        {
          name: "AIChat",
          type: "Component",
          confidence: 0.89
        }
      ],
      security_risks: securityRisks,
      code_references: enhancedCodeReferences,
      confidence_score: 0.85,
      remediation_suggestions: [
        "Store authentication tokens in HttpOnly cookies instead of localStorage",
        "Use environment variables for API keys and ensure they are not exposed to the client",
        "Implement proper HTTPS for all API communications",
        "Add rate limiting to AI service calls to prevent abuse",
        "Implement content filtering for user inputs to AI components"
      ]
    };
    
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
