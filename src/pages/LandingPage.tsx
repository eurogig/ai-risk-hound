
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Dog } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";

const LandingPage = () => {
  const [apiKey, setApiKey] = useState("");
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!apiKey) {
      toast({
        title: "API Key Required",
        description: "Please enter your OpenAI API key to continue.",
        variant: "destructive",
      });
      return;
    }
    
    setIsLoading(true);
    
    try {
      // Verify the API key is valid by making a simple request
      const response = await fetch("https://api.openai.com/v1/models", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
      });
      
      if (!response.ok) {
        throw new Error("Invalid API key. Please check and try again.");
      }
      
      // Store the API key in localStorage
      localStorage.setItem("openai_api_key", apiKey);
      
      // Store email if provided (optional)
      if (email) {
        localStorage.setItem("user_email", email);
      }
      
      toast({
        title: "Success!",
        description: "Your API key has been verified. Redirecting to the app...",
      });
      
      // Navigate to the main app
      setTimeout(() => navigate("/app"), 1500);
    } catch (error) {
      console.error("API Key validation error:", error);
      toast({
        title: "Authentication Failed",
        description: error.message || "Could not verify your API key. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        <Card className="shadow-lg">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <Dog className="h-12 w-12 text-purple-600" />
                <div className="absolute top-2 left-2 w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                <div className="absolute top-2 right-2 w-2 h-2 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.5s'}}></div>
              </div>
            </div>
            <CardTitle className="text-2xl font-bold">Welcome to RiskRover</CardTitle>
            <CardDescription>
              Analyze GitHub repositories for AI components and security risks
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="apiKey">OpenAI API Key <span className="text-red-500">*</span></Label>
                <Input
                  id="apiKey"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="sk-..."
                  required
                />
                <p className="text-xs text-gray-500">
                  Your API key is stored locally and is only used for repository analysis.
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="email">Email (Optional)</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="yourname@example.com"
                />
                <p className="text-xs text-gray-500">
                  We'll use this to notify you about important updates.
                </p>
              </div>
              
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Verifying..." : "Continue to RiskRover"}
              </Button>
            </form>
          </CardContent>
          <CardFooter className="text-xs text-center text-gray-500 flex-col space-y-2">
            <p>
              Don't have an OpenAI API key? <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Get one here</a>.
            </p>
            <p>
              Your API key is stored locally in your browser and never sent to our servers.
            </p>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
};

export default LandingPage;
