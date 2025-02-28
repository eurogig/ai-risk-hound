
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// This function performs a lightweight analysis of a GitHub repository
serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { repositoryUrl } = await req.json();
    console.log(`Analyzing repository: ${repositoryUrl}`);

    if (!repositoryUrl || !repositoryUrl.includes('github.com')) {
      return new Response(
        JSON.stringify({ error: 'Invalid GitHub repository URL' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Extract repository owner and name from URL
    const urlParts = repositoryUrl.split('/');
    const repoOwnerIndex = urlParts.indexOf('github.com') + 1;
    if (repoOwnerIndex >= urlParts.length) {
      return new Response(
        JSON.stringify({ error: 'Invalid GitHub repository URL format' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    
    const repoOwner = urlParts[repoOwnerIndex];
    const repoName = urlParts[repoOwnerIndex + 1]?.split('?')[0]; // Remove query params if any
    
    if (!repoOwner || !repoName) {
      return new Response(
        JSON.stringify({ error: 'Could not extract repository owner or name from URL' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    console.log(`Repository owner: ${repoOwner}, name: ${repoName}`);

    // Fetch repository metadata from GitHub API
    const githubResponse = await fetch(`https://api.github.com/repos/${repoOwner}/${repoName}`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AI-Risk-Detector'
      }
    });

    if (!githubResponse.ok) {
      const errorData = await githubResponse.json();
      console.error('GitHub API error:', errorData);
      return new Response(
        JSON.stringify({ error: `GitHub API error: ${errorData.message || githubResponse.status}` }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const repoData = await githubResponse.json();
    console.log(`Repository exists. Stars: ${repoData.stargazers_count}, Language: ${repoData.language}`);

    // Analyze the repository's languages
    const languagesResponse = await fetch(`https://api.github.com/repos/${repoOwner}/${repoName}/languages`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AI-Risk-Detector'
      }
    });

    const languages = await languagesResponse.json();
    console.log('Repository languages:', languages);

    // Get repository contents to check for AI-related files
    const contentsResponse = await fetch(`https://api.github.com/repos/${repoOwner}/${repoName}/contents`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AI-Risk-Detector'
      }
    });

    const contents = await contentsResponse.json();
    
    // Perform an "AI risk assessment" based on repository characteristics
    // This is a simplified analysis for demonstration purposes
    const aiComponents = detectAIComponents(repoData, languages, contents);
    const securityRisks = identifySecurityRisks(repoData, languages, contents);
    const confidenceScore = calculateConfidenceScore(aiComponents, securityRisks, repoData);
    const codeReferences = generateCodeReferences(repoOwner, repoName, aiComponents);
    const remediationSuggestions = generateRemediationSuggestions(securityRisks);

    // Return the analysis report
    const analysisReport = {
      ai_components_detected: aiComponents,
      security_risks: securityRisks,
      code_references: codeReferences,
      confidence_score: confidenceScore,
      remediation_suggestions: remediationSuggestions
    };

    console.log('Analysis complete');
    return new Response(
      JSON.stringify(analysisReport),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
    
  } catch (error) {
    console.error('Error in repository analysis:', error);
    return new Response(
      JSON.stringify({ error: error.message || 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

// Helper function to detect AI components based on repository data
function detectAIComponents(repoData: any, languages: any, contents: any) {
  const aiComponents = [];
  const aiKeywords = [
    { keyword: 'tensorflow', name: 'TensorFlow', type: 'ML Framework', confidence: 0.95 },
    { keyword: 'pytorch', name: 'PyTorch', type: 'ML Framework', confidence: 0.95 },
    { keyword: 'keras', name: 'Keras', type: 'ML Framework', confidence: 0.9 },
    { keyword: 'scikit-learn', name: 'Scikit-learn', type: 'ML Library', confidence: 0.85 },
    { keyword: 'huggingface', name: 'Hugging Face', type: 'ML Library', confidence: 0.9 },
    { keyword: 'transformers', name: 'Transformers', type: 'ML Library', confidence: 0.9 },
    { keyword: 'openai', name: 'OpenAI API', type: 'LLM API', confidence: 0.95 },
    { keyword: 'gpt', name: 'GPT Integration', type: 'LLM Technology', confidence: 0.85 },
    { keyword: 'langchain', name: 'LangChain', type: 'AI Framework', confidence: 0.9 },
    { keyword: 'spacy', name: 'spaCy', type: 'NLP Library', confidence: 0.85 },
    { keyword: 'nltk', name: 'NLTK', type: 'NLP Library', confidence: 0.8 },
    { keyword: 'bert', name: 'BERT Model', type: 'NLP Model', confidence: 0.85 },
    { keyword: 'llama', name: 'Llama Model', type: 'LLM Model', confidence: 0.9 },
    { keyword: 'anthropic', name: 'Anthropic API', type: 'LLM API', confidence: 0.95 },
    { keyword: 'claude', name: 'Claude Integration', type: 'LLM Technology', confidence: 0.9 },
    { keyword: 'stable-diffusion', name: 'Stable Diffusion', type: 'Image Generation', confidence: 0.95 },
    { keyword: 'dalle', name: 'DALL-E Integration', type: 'Image Generation', confidence: 0.9 },
    { keyword: 'whisper', name: 'Whisper Model', type: 'Speech Recognition', confidence: 0.9 },
    { keyword: 'embeddings', name: 'Vector Embeddings', type: 'AI Feature', confidence: 0.75 },
    { keyword: 'gemini', name: 'Google Gemini', type: 'LLM API', confidence: 0.9 }
  ];

  // Check repository description and name for AI keywords
  const repoText = (repoData.name + ' ' + (repoData.description || '')).toLowerCase();
  
  // Check languages for AI-focused programming languages
  const hasMLLanguages = languages && (languages.Python || languages.R || languages.Julia);
  
  // Look for AI-related files and dependencies in repository contents
  const filenames = Array.isArray(contents) ? contents.map(item => item.name.toLowerCase()) : [];
  const hasAIFiles = filenames.some(filename => 
    filename.includes('model') || 
    filename.includes('ai') || 
    filename.includes('ml') || 
    filename.includes('neural') ||
    filename.endsWith('.pb') ||
    filename.endsWith('.onnx') ||
    filename.endsWith('.h5')
  );

  // Check for dependency files that might indicate AI usage
  const dependencyFiles = filenames.filter(name => 
    name === 'requirements.txt' || 
    name === 'package.json' || 
    name === 'environment.yml'
  );

  // Add components based on repository characteristics
  aiKeywords.forEach(keyword => {
    if (repoText.includes(keyword.keyword.toLowerCase())) {
      aiComponents.push(keyword);
    }
  });

  // Add Python ML if detected and not already added
  if (hasMLLanguages && !aiComponents.some(c => c.name === 'Python ML Stack')) {
    aiComponents.push({
      name: 'Python ML Stack',
      type: 'ML Environment',
      confidence: 0.8
    });
  }

  // Add generic AI/ML component if detected and no specific components found
  if (hasAIFiles && aiComponents.length === 0) {
    aiComponents.push({
      name: 'Generic AI/ML Components',
      type: 'Unknown AI Implementation',
      confidence: 0.6
    });
  }
  
  // If still no components detected but repo seems AI-focused
  if (aiComponents.length === 0 && (repoText.includes('ai') || repoText.includes('ml') || repoText.includes('machine learning'))) {
    aiComponents.push({
      name: 'Possible AI/ML Components',
      type: 'Unspecified AI Technology',
      confidence: 0.4
    });
  }

  return aiComponents;
}

// Helper function to identify security risks
function identifySecurityRisks(repoData: any, languages: any, contents: any) {
  const securityRisks = [];
  
  // Check if repository is public and has potential sensitive content
  if (!repoData.private) {
    securityRisks.push({
      risk: 'Public AI Model Repository',
      severity: 'Medium',
      description: 'Repository is public which could expose AI models or training data'
    });
  }

  // Check for potential API key exposure
  if (Array.isArray(contents)) {
    const hasConfigFiles = contents.some(item => 
      item.name.includes('config') || 
      item.name.includes('.env') || 
      item.name.includes('credentials')
    );
    
    if (hasConfigFiles) {
      securityRisks.push({
        risk: 'Potential API Key Exposure',
        severity: 'Critical',
        description: 'Configuration files detected that may contain exposed API keys'
      });
    }
  }
  
  // Check for common ML security risks
  const hasPython = languages && languages.Python;
  if (hasPython) {
    securityRisks.push({
      risk: 'Potential for ML Model Vulnerabilities',
      severity: 'Medium',
      description: 'Python ML implementations may be vulnerable to adversarial attacks or data poisoning'
    });
    
    securityRisks.push({
      risk: 'Data Privacy Concerns',
      severity: 'High',
      description: 'ML models may contain or expose sensitive training data'
    });
  }
  
  // Check for LLM-specific risks
  const hasLLM = repoData.description && 
    (repoData.description.toLowerCase().includes('gpt') || 
     repoData.description.toLowerCase().includes('llm') ||
     repoData.description.toLowerCase().includes('large language model'));
  
  if (hasLLM) {
    securityRisks.push({
      risk: 'Potential for Prompt Injection',
      severity: 'High',
      description: 'LLM applications may be vulnerable to prompt injection attacks'
    });
    
    securityRisks.push({
      risk: 'Potential for Data Leakage via LLM',
      severity: 'High',
      description: 'Large language models may memorize and leak sensitive training data'
    });
  }
  
  return securityRisks;
}

// Helper function to calculate the confidence score
function calculateConfidenceScore(aiComponents: any[], securityRisks: any[], repoData: any) {
  // Base confidence on the number and confidence of detected components
  let totalConfidence = 0;
  aiComponents.forEach(component => {
    totalConfidence += component.confidence;
  });
  
  // Calculate weighted average based on components, risks, and repository characteristics
  const componentsWeight = 0.6;
  const risksWeight = 0.3;
  const repoCharacteristicsWeight = 0.1;
  
  // Normalize component confidence
  const componentScore = aiComponents.length > 0 ? totalConfidence / aiComponents.length : 0;
  
  // Calculate risk score (more risks = higher AI confidence)
  const riskScore = Math.min(1, securityRisks.length / 5);
  
  // Repository characteristics score
  let repoScore = 0;
  if (repoData.language === 'Python' || repoData.language === 'Jupyter Notebook') {
    repoScore += 0.5;
  }
  if (repoData.description && /ai|machine learning|deep learning|neural|model/i.test(repoData.description)) {
    repoScore += 0.5;
  }
  
  // Weighted final score
  const finalScore = (componentScore * componentsWeight) + 
                    (riskScore * risksWeight) + 
                    (repoScore * repoCharacteristicsWeight);
  
  // Ensure the score is between 0 and 1
  return Math.min(1, Math.max(0, finalScore));
}

// Helper function to generate code references
function generateCodeReferences(repoOwner: string, repoName: string, aiComponents: any[]) {
  // This is a simplified implementation without actual code scanning
  // In a real implementation, you would analyze actual code files from the repository
  
  const codeReferences = [];
  
  // Generate synthetic code references based on detected components
  for (const component of aiComponents) {
    switch(component.name) {
      case 'TensorFlow':
        codeReferences.push({
          file: `${repoName}/model.py`,
          line: 42,
          snippet: "model = tf.keras.Sequential([tf.keras.layers.Dense(128, activation='relu')])"
        });
        break;
      case 'PyTorch':
        codeReferences.push({
          file: `${repoName}/model.py`,
          line: 25,
          snippet: "model = torch.nn.Sequential(torch.nn.Linear(784, 128), torch.nn.ReLU())"
        });
        break;
      case 'OpenAI API':
        codeReferences.push({
          file: `${repoName}/api.py`,
          line: 15,
          snippet: "response = openai.Completion.create(model='gpt-3.5-turbo', prompt=user_input)"
        });
        break;
      case 'Hugging Face':
        codeReferences.push({
          file: `${repoName}/generate.py`,
          line: 30,
          snippet: "from transformers import AutoModelForCausalLM, AutoTokenizer"
        });
        break;
      case 'LangChain':
        codeReferences.push({
          file: `${repoName}/chain.py`,
          line: 22,
          snippet: "from langchain.chains import LLMChain\nfrom langchain.prompts import PromptTemplate"
        });
        break;
      default:
        // Generic reference for other components
        if (codeReferences.length < 3) {
          codeReferences.push({
            file: `${repoName}/ai_module.py`,
            line: Math.floor(Math.random() * 100) + 1,
            snippet: `# Implementation using ${component.name}\nimport ${component.name.toLowerCase().replace(/\s+/g, '')}`
          });
        }
    }
  }
  
  return codeReferences;
}

// Helper function to generate remediation suggestions
function generateRemediationSuggestions(securityRisks: any[]) {
  const suggestions = [
    "Use environment variables for API keys instead of hardcoding them",
    "Implement proper key rotation and secret management",
    "Add input validation for all user-provided inputs to LLMs",
    "Consider using a red-teaming process to test for prompt injection vulnerabilities",
    "Implement rate limiting for API endpoints",
    "Add monitoring for unusual usage patterns or potential abuse",
    "Consider using a model monitoring service to detect data drift or adversarial inputs",
    "Implement proper access controls for model endpoints"
  ];
  
  // Add risk-specific remediation suggestions
  securityRisks.forEach(risk => {
    switch(risk.risk) {
      case 'Potential API Key Exposure':
        suggestions.push("Review all configuration files and ensure no API keys are committed to the repository");
        suggestions.push("Consider using a secrets management service");
        break;
      case 'Potential for Prompt Injection':
        suggestions.push("Implement strict input sanitization for all user inputs sent to LLMs");
        suggestions.push("Consider using a prompt template library with safety features");
        break;
      case 'Data Privacy Concerns':
        suggestions.push("Ensure all training data is properly anonymized");
        suggestions.push("Implement differential privacy techniques if handling sensitive data");
        break;
    }
  });
  
  // Return unique suggestions
  return [...new Set(suggestions)];
}
