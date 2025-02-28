
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dog, BarChart2, LogOut } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/components/ui/use-toast";

const Navigation = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleLogout = () => {
    // Remove the API key from localStorage
    localStorage.removeItem("openai_api_key");
    localStorage.removeItem("user_email");
    
    toast({
      title: "Logged Out",
      description: "Your API key has been removed from this device.",
    });
    
    // Redirect to landing page
    navigate("/");
  };

  return (
    <nav className="bg-white shadow-sm py-4">
      <div className="max-w-6xl mx-auto px-4 flex justify-between items-center">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Dog className="h-6 w-6 text-purple-600" />
            {/* Cyber elements overlay */}
            <div className="absolute top-1 left-1 w-1 h-1 bg-blue-400 rounded-full animate-pulse"></div>
            <div className="absolute top-1 right-1 w-1 h-1 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.5s'}}></div>
          </div>
          <span className="font-bold text-xl">RiskRover</span>
        </div>
        
        <div className="flex space-x-2">
          <Link to="/app">
            <Button 
              variant={location.pathname === "/app" ? "default" : "outline"}
            >
              New Analysis
            </Button>
          </Link>
          <Link to="/history">
            <Button 
              variant={location.pathname === "/history" ? "default" : "outline"}
            >
              <BarChart2 className="mr-2 h-4 w-4" />
              History
            </Button>
          </Link>
          <Button 
            variant="outline" 
            onClick={handleLogout}
          >
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </Button>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
