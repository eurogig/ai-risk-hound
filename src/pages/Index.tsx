
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import ReportResults from "@/components/ReportResults";
import { useToast } from "@/components/ui/use-toast";
import Navigation from "@/components/Navigation";

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

// Mock data for simulation mode
const generateMockReport = (repositoryUrl: string): RepositoryReport => {
  // Extract repo name for personalization
  const repoName = repositoryUrl.split('/').pop() || "repository";
  
  return {
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
      },
      {
        name: "Hugging Face Transformers",
        type: "ML Library",
        confidence: 0.78
      }
    ],
    security_risks: [
      {
        risk: "API Key Exposure",
        severity: "Critical",
        description: `API key found hardcoded in ${repoName} source files`
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
        file: `${repoName}/src/utils/api.js`,
        line: 15,
        snippet: "const OPENAI_API_KEY = 'sk-...';"
      },
      {
        file: `${repoName}/src/components/ChatBox.jsx`,
        line: 42,
        snippet: "const response = await openai.chat.completions.create({ messages: [userInput] });"
      },
      {
        file: `${repoName}/server/routes/ai.js`,
        line: 27,
        snippet: "const embedding = await model.embed(userQuery);"
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
};

const Index = () => {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<RepositoryReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!repositoryUrl) {
      setError("Please enter a GitHub repository URL");
      return;
    }
    
    // Validate GitHub URL format
    const isGitHubUrl = /https?:\/\/github\.com\/[^\/]+\/[^\/]+/.test(repositoryUrl);
    if (!isGitHubUrl) {
      setError("Please enter a valid GitHub repository URL (e.g., https://github.com/username/repository)");
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      // Simulate a network request with a short delay
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Generate mock report data
      const mockReport = generateMockReport(repositoryUrl);
      setReport(mockReport);
      
      toast({
        title: "Analysis Complete",
        description: "Repository analysis has been completed successfully.",
      });
      
      console.log("Using simulation mode - Supabase functions are not yet deployed");
    } catch (err) {
      console.error('Error generating report:', err);
      setError("Failed to analyze repository. Please try again later.");
      
      toast({
        title: "Analysis Failed",
        description: "Failed to analyze repository. Please try again later.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 flex flex-col">
      <Navigation />
      <div className="flex-1 flex flex-col items-center justify-center px-4 py-12">
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
          
          <div className="p-4 bg-amber-50 border border-amber-200 rounded-md text-amber-800 text-sm">
            <p className="font-medium">Note: Simulation Mode Active</p>
            <p>The application is currently running in simulation mode. The analysis results are generated for demonstration purposes only.</p>
          </div>
          
          {report && !isLoading && (
            <ReportResults report={report} />
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
