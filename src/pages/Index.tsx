
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import ReportResults from "@/components/ReportResults";

interface RepositoryReport {
  ai_components_detected: {
    name: string;
    type: string;
    confidence: number;
  }[];
  security_risks: {
    risk: string;
    severity: string;
    description: string;
  }[];
  code_references: {
    file: string;
    line: number;
    snippet: string;
  }[];
  confidence_score: number;
  remediation_suggestions: string[];
}

const Index = () => {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<RepositoryReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!repositoryUrl) {
      setError("Please enter a GitHub repository URL");
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      // In a real implementation, this would call your API
      // For demo purposes, we'll simulate an API call with mock data
      const response = await simulateApiCall(repositoryUrl);
      setReport(response);
    } catch (err) {
      setError("Failed to analyze repository. Please check the URL and try again.");
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  // This function simulates an API call with mock data
  const simulateApiCall = async (repoUrl: string): Promise<RepositoryReport> => {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check if URL contains "openai" to generate different mock responses
    const isAIRepo = repoUrl.toLowerCase().includes("openai") || 
                      repoUrl.toLowerCase().includes("ai") || 
                      repoUrl.toLowerCase().includes("gpt");
    
    if (isAIRepo) {
      return {
        ai_components_detected: [
          { name: "OpenAI API", type: "LLM API", confidence: 0.98 },
          { name: "Transformers", type: "ML Framework", confidence: 0.85 },
          { name: "Langchain", type: "AI Framework", confidence: 0.92 }
        ],
        security_risks: [
          { risk: "Prompt Injection", severity: "High", description: "Unvalidated user input passed directly to LLM" },
          { risk: "API Key Exposure", severity: "Critical", description: "API keys found in source code" },
          { risk: "Data Exfiltration", severity: "Medium", description: "Sensitive data might be sent to external APIs" }
        ],
        code_references: [
          { file: "app.py", line: 42, snippet: "response = openai.ChatCompletion.create(model='gpt-4', messages=[...])" },
          { file: "utils/ai.js", line: 17, snippet: "const API_KEY = 'sk-...';" },
          { file: "services/assistant.py", line: 128, snippet: "return llm.generate(user_data + system_prompt)" }
        ],
        confidence_score: 0.94,
        remediation_suggestions: [
          "Use environment variables for API keys instead of hardcoding them",
          "Implement input validation before passing to LLM",
          "Set up content filtering for LLM inputs and outputs",
          "Implement rate limiting for API requests",
          "Use a dedicated service account with minimal permissions"
        ]
      };
    } else {
      return {
        ai_components_detected: [],
        security_risks: [
          { risk: "No AI components detected", severity: "Info", description: "This repository does not appear to contain AI components" }
        ],
        code_references: [],
        confidence_score: 0.05,
        remediation_suggestions: [
          "No AI-specific remediation needed"
        ]
      };
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-2xl mx-auto space-y-8">
        <div className="text-center space-y-4">
          <h1 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">
            AI Risk Detector
          </h1>
          <p className="text-lg text-gray-600">
            Scan your GitHub repository for AI components and security risks
          </p>
        </div>
        
        <Card className="p-6 shadow-lg bg-white">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="repository-url" className="block text-sm font-medium text-gray-700">
                GitHub Repository URL
              </label>
              <Input
                id="repository-url"
                placeholder="https://github.com/username/repository"
                value={repositoryUrl}
                onChange={(e) => setRepositoryUrl(e.target.value)}
                className="w-full"
                disabled={isLoading}
              />
              {error && <p className="text-sm text-red-500">{error}</p>}
            </div>
            
            <Button 
              type="submit" 
              className="w-full"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analyzing Repository...
                </>
              ) : (
                "Analyze Repository"
              )}
            </Button>
          </form>
        </Card>
        
        {report && !isLoading && (
          <ReportResults report={report} />
        )}
      </div>
    </div>
  );
};

export default Index;
