
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
      // Use hardcoded Supabase URL and key
      const supabaseUrl = "https://bnmbrtsyqxqoitrcesgu.supabase.co";
      const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJubWJydHN5cXhxb2l0cmNlc2d1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDA3MDEyNDgsImV4cCI6MjA1NjI3NzI0OH0.PT-jorVmwDQIG0iKQ5bI2nCEClMxkoBv8yfRdu9-7XA";
      
      // Use the comprehensive analysis function instead of the simplified one
      const endpoint = `${supabaseUrl}/functions/v1/analyze-repository`;
      
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
          
          Specifically look for these RAG (Retrieval Augmented Generation) components:
          - Vector databases: FAISS, Pinecone, Weaviate, ChromaDB, Qdrant
          - Embedding generation libraries: sentence-transformers, OpenAI embeddings, HuggingFace embeddings
          - Search integrations for document retrieval
          
          Only flag "Potential for Data Leakage via LLM" as a security risk if RAG components are detected alongside LLM usage.
          Without RAG components, standard LLM integration poses lower data leakage risk.`
        }
      };
      
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
        } catch (e) {
          errorMessage = `HTTP error: ${response.status}`;
        }
        throw new Error(errorMessage);
      }
      
      const data = await response.json();
      setReport(data);
      
      toast({
        title: "Analysis Complete",
        description: "Comprehensive repository analysis has been completed successfully.",
      });
    } catch (err) {
      console.error('Error analyzing repository:', err);
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
          
          {report && !isLoading && (
            <ReportResults report={report} />
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
