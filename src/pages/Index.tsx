
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import ReportResults from "@/components/ReportResults";
import { useToast } from "@/components/ui/use-toast";
import Navigation from "@/components/Navigation";
import { supabase } from "@/integrations/supabase/client";
import { RepositoryReport } from "@/types/reportTypes";

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
      addLog(`Sending request to analyze repository: ${repositoryUrl}`);
      
      toast({
        title: "Analysis Started",
        description: "This comprehensive analysis may take a bit longer. Please wait...",
      });
      
      // Get user's API key from localStorage
      const userApiKey = localStorage.getItem("openai_api_key");
      if (!userApiKey) {
        throw new Error("No API key found. Please log in again.");
      }
      
      // Use the Supabase Functions API through the client instead of hardcoded credentials
      const { data, error: functionError } = await supabase.functions.invoke('analyze-repository', {
        body: {
          repositoryUrl,
          apiKey: userApiKey, // Pass the user's API key
          options: {
            systemPrompt: `Analyze the GitHub repository and provide insights about AI components and security risks. 
            
            When analyzing repositories:
            1. Only report code references that you can confirm exist in the repository. 
            2. Do not invent or hallucinate file paths or code snippets.
            3. If uncertain about specific files, focus on identifying patterns and general concerns instead.
            4. If you cannot find specific code references, leave that section empty rather than making suggestions.
            
            IMPORTANT: Look carefully for HARDCODED SYSTEM PROMPTS in Python, TypeScript, and JavaScript files:
            - Check for string assignments like SYSTEM_PROMPT = "You are an AI assistant..."
            - Check for hardcoded function arguments like messages=[{"role": "system", "content": "You are helpful."}]
            - These are security risks because they can leak information or be manipulated
            - Report them under "System Prompt Leakage" risk category
            
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
        }
      });
      
      if (functionError) {
        throw new Error(functionError.message || "Failed to analyze repository");
      }
      
      addLog("Received successful response");
      
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
      
      // Save the analysis result to the database
      await saveAnalysisToDatabase(repositoryUrl, data);
      
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

  const saveAnalysisToDatabase = async (repositoryUrl: string, analysisResult: any) => {
    try {
      addLog(`Saving analysis results to database for: ${repositoryUrl}`);
      
      // First, delete old repository analyses (older than 7 days)
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      
      const { error: deleteError, count } = await supabase
        .from('repository_analyses')
        .delete({ count: 'exact' })
        .lt('created_at', oneWeekAgo.toISOString());
      
      if (deleteError) {
        console.error('Error deleting old analyses:', deleteError);
        addLog(`Failed to clean up old analyses: ${deleteError.message}`);
      } else if (count && count > 0) {
        addLog(`Cleaned up ${count} old repository analyses`);
      }
      
      // Now save the new analysis
      const { error } = await supabase
        .from('repository_analyses')
        .insert({
          repository_url: repositoryUrl,
          analysis_result: analysisResult as any
        });
      
      if (error) {
        if (error.code === '42501') { // Permission denied error
          addLog('Permission denied: Cannot save analysis without authentication');
          toast({
            title: "Notice",
            description: "Analysis results will not be saved to history (authentication required).",
          });
          return;
        }
        throw error;
      }
      
      addLog('Analysis saved to database successfully');
      toast({
        title: "Saved to History",
        description: "This analysis has been saved and can be viewed in the History tab.",
      });
    } catch (err) {
      console.error('Error saving to database:', err);
      addLog(`Database error: ${err.message}`);
      toast({
        title: "Warning",
        description: "Analysis completed but could not save to history.",
        variant: "destructive",
      });
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
              RiskRover
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
