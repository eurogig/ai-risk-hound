
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

const Index = () => {
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<RepositoryReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [debugLogs, setDebugLogs] = useState<string[]>([]);
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
    setDebugLogs([]); // Clear previous logs
    
    try {
      // Use hardcoded Supabase URL and key
      const supabaseUrl = "https://bnmbrtsyqxqoitrcesgu.supabase.co";
      const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJubWJydHN5cXhxb2l0cmNlc2d1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDA3MDEyNDgsImV4cCI6MjA1NjI3NzI0OH0.PT-jorVmwDQIG0iKQ5bI2nCEClMxkoBv8yfRdu9-7XA";
      
      // Use the comprehensive analysis function instead of the simplified one
      const endpoint = `${supabaseUrl}/functions/v1/analyze-repository`;
      
      addLog(`Sending request to: ${endpoint}`);
      console.log("Sending request to:", endpoint);
      
      toast({
        title: "Analysis Started",
        description: "This comprehensive analysis may take a bit longer. Please wait...",
      });
      
      // Include specific system prompt instructions to reduce hallucinations and detect RAG components
      const payload = {
        repositoryUrl,
        options: {
          systemPrompt: `Analyze the GitHub repository and provide insights about AI components and security risks. 
          
          When analyzing repositories:
          1. Only report code references that you can confirm exist in the repository. 
          2. Do not invent or hallucinate file paths or code snippets.
          3. If uncertain about specific files, focus on identifying patterns and general concerns instead.
          4. If you cannot find specific code references, leave that section empty rather than making suggestions.
          
          IMPORTANT: This repository may have a nested structure. Make sure to:
          - Recursively check all directories and subdirectories
          - Look for all requirements.txt, package.json, or other dependency files in ALL subdirectories
          - Pay special attention to Python files (.py) that may contain imports of AI libraries
          - Check for OpenAI, LangChain, HuggingFace, and other AI framework imports or usages
          
          Specifically look for these RAG (Retrieval Augmented Generation) components:
          - Vector databases: FAISS, Pinecone, Weaviate, ChromaDB, Qdrant
          - Embedding generation libraries: sentence-transformers, OpenAI embeddings, HuggingFace embeddings
          - Search integrations for document retrieval
          
          Only flag "Potential for Data Leakage via LLM" as a security risk if RAG components are detected alongside LLM usage.
          Without RAG components, standard LLM integration poses lower data leakage risk.`
        },
        debugMode: true // Enable detailed debug information
      };
      
      addLog(`Payload: ${JSON.stringify(payload, null, 2)}`);
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${supabaseKey}`
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        let errorMessage;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || `HTTP error: ${response.status}`;
          addLog(`Error response: ${JSON.stringify(errorData, null, 2)}`);
        } catch (e) {
          errorMessage = `HTTP error: ${response.status}`;
          addLog(`Failed to parse error response: ${e.message}`);
        }
        throw new Error(errorMessage);
      }
      
      addLog("Received successful response");
      const data = await response.json();
      
      if (data.debug) {
        addLog(`Debug info: ${JSON.stringify(data.debug, null, 2)}`);
        console.log("Debug info:", data.debug);
      }
      
      // Log some statistics about what was found
      if (data.code_references) {
        addLog(`Found ${data.code_references.length} code references`);
        const fileTypes = new Set(data.code_references.map(ref => {
          const parts = ref.file.split('.');
          return parts.length > 1 ? parts.pop() : 'unknown';
        }));
        addLog(`File types found: ${Array.from(fileTypes).join(', ')}`);
      }
      
      if (data.ai_components_detected) {
        addLog(`Found ${data.ai_components_detected.length} AI components`);
      }
      
      setReport(data);
      
      toast({
        title: "Analysis Complete",
        description: "Comprehensive repository analysis has been completed successfully.",
      });
    } catch (err) {
      console.error('Error analyzing repository:', err);
      addLog(`Error: ${err.message || "Unknown error"}`);
      setError(err.message || "Failed to analyze repository. Please check the URL and try again.");
      
      toast({
        title: "Analysis Failed",
        description: err.message || "Failed to analyze repository. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const addLog = (message: string) => {
    console.log(message);
    setDebugLogs(prev => [...prev, `[${new Date().toISOString()}] ${message}`]);
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
          
          {/* Debug Logs Panel - Collapsible */}
          {debugLogs.length > 0 && (
            <Card className="p-4 bg-gray-800 text-white overflow-auto max-h-60">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-sm font-mono">Debug Logs</h3>
                <Button 
                  variant="outline" 
                  size="sm"
                  className="h-6 text-xs border-gray-600 text-gray-300 hover:text-white hover:bg-gray-700"
                  onClick={() => setDebugLogs([])}
                >
                  Clear Logs
                </Button>
              </div>
              <div className="space-y-1 font-mono text-xs">
                {debugLogs.map((log, index) => (
                  <div key={index} className="whitespace-pre-wrap break-all">{log}</div>
                ))}
              </div>
            </Card>
          )}
          
          {report && !isLoading && (
            <ReportResults report={report} />
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
