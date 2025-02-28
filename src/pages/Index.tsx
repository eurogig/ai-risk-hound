
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
      // Use the Supabase URL and key from environment variables
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
      const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
      
      if (!supabaseUrl || !supabaseKey) {
        throw new Error("Supabase configuration is missing. Please check your environment variables.");
      }
      
      // Try the simplified function first as it's more lightweight
      const endpoint = `${supabaseUrl}/functions/v1/analyze-repository-simple`;
      
      console.log("Sending request to:", endpoint);
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${supabaseKey}`
        },
        body: JSON.stringify({ repositoryUrl })
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
        description: "Repository analysis has been completed successfully.",
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
