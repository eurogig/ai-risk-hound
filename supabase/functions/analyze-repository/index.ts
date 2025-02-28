
// Import necessary modules
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from '@supabase/supabase-js';

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse the request
    const { repositoryUrl, apiKey, options, debugMode } = await req.json();
    
    if (!repositoryUrl) {
      return new Response(
        JSON.stringify({ error: 'Repository URL is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    if (!apiKey) {
      return new Response(
        JSON.stringify({ error: 'API key is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Set up debug information if debug mode is enabled
    const debugInfo = debugMode ? { steps: [], timing: {} } : null;
    if (debugInfo) {
      debugInfo.timing.start = new Date().toISOString();
      debugInfo.steps.push(`Analysis started for repository: ${repositoryUrl}`);
    }

    // Make the API request to OpenAI
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: options?.model || 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: options?.systemPrompt || `You are a GitHub repository security scanner that specializes in AI and LLM applications.`
          },
          {
            role: 'user',
            content: `Analyze this GitHub repository: ${repositoryUrl}`
          }
        ],
        temperature: options?.temperature || 0.1,
      }),
    });

    if (debugInfo) {
      debugInfo.steps.push('Received response from OpenAI API');
      debugInfo.timing.openAiResponse = new Date().toISOString();
    }

    // Check if the response was successful
    if (!response.ok) {
      const errorData = await response.json();
      if (debugInfo) {
        debugInfo.steps.push(`OpenAI API error: ${JSON.stringify(errorData)}`);
      }
      
      console.error('OpenAI API error:', errorData);
      
      return new Response(
        JSON.stringify({ error: 'Failed to analyze repository', details: errorData }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Parse the response
    const data = await response.json();
    
    if (debugInfo) {
      debugInfo.steps.push('Parsed OpenAI response');
    }

    // Extract content from the response
    const analysisText = data.choices[0].message.content;
    
    if (debugInfo) {
      debugInfo.steps.push('Extracted analysis content');
      debugInfo.rawAnalysis = analysisText.substring(0, 500) + '...'; // First 500 chars for debug
    }

    // Try to parse the JSON from the response
    let analysisResult;
    try {
      // Look for JSON in the response
      const jsonMatch = analysisText.match(/```json\n([\s\S]*?)\n```/) || 
                        analysisText.match(/{[\s\S]*}/);
      
      const jsonContent = jsonMatch ? jsonMatch[1] || jsonMatch[0] : analysisText;
      
      // Clean the JSON string and parse it
      const cleanedJson = jsonContent.replace(/```json|```/g, '').trim();
      analysisResult = JSON.parse(cleanedJson);
      
      if (debugInfo) {
        debugInfo.steps.push('Successfully parsed JSON from response');
      }
    } catch (error) {
      if (debugInfo) {
        debugInfo.steps.push(`Failed to parse JSON: ${error.message}`);
        debugInfo.jsonParsingError = error.message;
        debugInfo.rawText = analysisText.substring(0, 1000) + '...'; // First 1000 chars for debug
      }
      
      console.error('Failed to parse JSON from OpenAI response:', error);
      console.log('Raw response:', analysisText);
      
      // Fallback: If the response isn't valid JSON, attempt to extract structured data
      analysisResult = {
        ai_components_detected: [],
        security_risks: [],
        code_references: [],
        confidence_score: 0.5,
        remediation_suggestions: []
      };

      // Search for hardcoded system prompts in the raw text
      if (analysisText.includes("system prompt") || analysisText.includes("hardcoded prompt")) {
        analysisResult.security_risks.push({
          risk: "Potential Hardcoded System Prompts",
          severity: "Medium",
          description: "Possible hardcoded system prompts detected but couldn't parse details.",
          related_code_references: []
        });
      }
    }

    // Ensure the analysis result has the expected structure
    const defaultResult = {
      ai_components_detected: [],
      security_risks: [],
      code_references: [],
      confidence_score: 0.5,
      remediation_suggestions: []
    };

    // Merge the parsed result with the default structure to ensure all fields exist
    const mergedResult = {
      ...defaultResult,
      ...analysisResult,
      ai_components_detected: analysisResult.ai_components_detected || [],
      security_risks: analysisResult.security_risks || [],
      code_references: analysisResult.code_references || [],
      remediation_suggestions: analysisResult.remediation_suggestions || []
    };

    // Process and detect hardcoded system prompts
    // but ENSURE we don't duplicate them if they already exist
    const hasSystemPromptRisk = mergedResult.security_risks.some(risk => {
      const riskName = risk.risk || risk.risk_name || '';
      return riskName.toLowerCase().includes('system prompt') || 
             riskName.toLowerCase().includes('hardcoded prompt');
    });

    // Detect hardcoded system prompts in code references
    const promptReferences = [];
    if (mergedResult.code_references && mergedResult.code_references.length > 0) {
      mergedResult.code_references.forEach(ref => {
        if (!ref || !ref.snippet) return;
        
        const snippet = ref.snippet.toLowerCase();
        // Check for patterns indicating system prompts
        const isSystemPrompt = (
          (snippet.includes('system') && snippet.includes('prompt')) ||
          (snippet.includes('role') && snippet.includes('system') && snippet.includes('content')) ||
          (snippet.includes('you are') && (snippet.includes('assistant') || snippet.includes('ai')))
        );

        if (isSystemPrompt) {
          // Create a unique ID if not present
          const id = ref.id || `${ref.file}-${ref.line}-${promptReferences.length}`;
          promptReferences.push({
            ...ref,
            id: id
          });
        }
      });

      // Log how many potential system prompts were found
      console.log(`Detected ${promptReferences.length} potential hardcoded system prompts`);
    }

    // Add system prompt risk only if it doesn't already exist and we found references
    if (!hasSystemPromptRisk && promptReferences.length > 0) {
      const systemPromptRisk = {
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
      
      mergedResult.security_risks.push(systemPromptRisk);
      
      // Add prompt references to code references if they don't already exist
      const existingIds = new Set(mergedResult.code_references.map(ref => ref.id));
      promptReferences.forEach(ref => {
        if (!existingIds.has(ref.id)) {
          mergedResult.code_references.push(ref);
        }
      });
    }

    // Standardize field names across all risks
    if (mergedResult.security_risks) {
      mergedResult.security_risks = mergedResult.security_risks.map(risk => {
        // Ensure risk name is consistent
        if (!risk.risk && risk.risk_name) {
          risk.risk = risk.risk_name;
        } else if (!risk.risk) {
          risk.risk = "Unknown Risk";
        }
        
        // Ensure other fields have default values
        if (!risk.severity) risk.severity = "Medium";
        if (!risk.description) risk.description = "No description provided.";
        if (!risk.related_code_references) risk.related_code_references = [];
        
        return risk;
      });
    }

    // Complete the debug information
    if (debugInfo) {
      debugInfo.steps.push('Analysis complete');
      debugInfo.timing.end = new Date().toISOString();
      
      // Add statistics for debugging
      debugInfo.stats = {
        aiComponentsCount: mergedResult.ai_components_detected.length,
        securityRisksCount: mergedResult.security_risks.length,
        codeReferencesCount: mergedResult.code_references.length,
        remediationSuggestionsCount: mergedResult.remediation_suggestions.length,
        confidenceScore: mergedResult.confidence_score
      };

      // Include debug information in the response if debug mode is enabled
      mergedResult.debug = debugInfo;
    }

    // Return the final analysis result
    return new Response(
      JSON.stringify(mergedResult),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Error in analyze-repository function:', error);
    
    return new Response(
      JSON.stringify({ error: error.message || 'An error occurred during analysis' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
