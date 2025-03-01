
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldAlert, CheckCircle, ExternalLink } from "lucide-react";

interface RemediationSuggestionsCardProps {
  suggestions: string[];
}

const RemediationSuggestionsCard = ({ suggestions }: RemediationSuggestionsCardProps) => {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl flex items-center gap-2">
          <CheckCircle className="h-5 w-5 text-green-500" />
          Remediation Suggestions
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <ul className="space-y-3">
            {suggestions.map((suggestion, index) => (
              <li key={index} className="flex items-start gap-2 p-2 hover:bg-gray-50 rounded-md transition-colors">
                <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                <div className="text-gray-700">{suggestion}</div>
              </li>
            ))}
          </ul>
          
          {/* OWASP LLM Top 10 Reference */}
          <div className="bg-blue-50 p-4 rounded-lg border border-blue-100">
            <h4 className="text-blue-800 font-semibold mb-1 flex items-center">
              <ShieldAlert className="h-4 w-4 mr-2" />
              OWASP LLM Top 10 Reference
            </h4>
            <p className="text-blue-700 text-sm">
              Security risks in this report are mapped to the OWASP LLM Top 10, a comprehensive guide to common security risks in LLM applications.
            </p>
            <div className="mt-3">
              <a 
                href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-blue-600 text-sm underline hover:text-blue-800 flex items-center gap-1"
              >
                Learn more about OWASP LLM Top 10
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
          
          {/* Recommendations Section */}
          <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
            <h4 className="font-semibold mb-2">Additional AI Security Resources</h4>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start gap-2">
                <span className="font-medium min-w-28">Input Validation:</span> 
                <span>Implement robust input validation and sanitization for all user inputs.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-medium min-w-28">Content Filtering:</span> 
                <span>Use content filtering systems to detect and prevent harmful outputs.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-medium min-w-28">Monitoring:</span> 
                <span>Implement comprehensive monitoring of LLM usage and responses.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-medium min-w-28">Model Versioning:</span> 
                <span>Track and manage model versions to ensure security updates.</span>
              </li>
            </ul>
          </div>
          
          {/* Call to Action Button */}
          <div className="pt-4 flex justify-center">
            <a href="https://www.straiker.ai/" target="_blank" rel="noopener noreferrer">
              <button className="bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 text-white px-6 py-3 rounded-lg shadow-lg flex items-center gap-2 transform transition-transform duration-200 hover:scale-105">
                <ShieldAlert className="h-5 w-5" />
                Get a Free AI Security Assessment
                <ExternalLink className="h-4 w-4 ml-2" />
              </button>
            </a>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default RemediationSuggestionsCard;
