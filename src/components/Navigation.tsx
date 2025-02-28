
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Dog, BarChart2 } from "lucide-react";

const Navigation = () => {
  const location = useLocation();

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
          <Link to="/">
            <Button 
              variant={location.pathname === "/" ? "default" : "outline"}
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
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
