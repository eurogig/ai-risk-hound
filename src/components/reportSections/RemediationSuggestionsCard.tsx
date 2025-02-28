
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ShieldAlert } from "lucide-react";

interface RemediationSuggestionsCardProps {
  suggestions: string[];
}

const RemediationSuggestionsCard = ({ suggestions }: RemediationSuggestionsCardProps) => {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">Remediation Suggestions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <ul className="space-y-2 list-disc pl-5">
            {suggestions.map((suggestion, index) => (
              <li key={index} className="text-gray-700">{suggestion}</li>
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
            <div className="mt-2">
              <a 
                href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-blue-600 text-sm underline hover:text-blue-800"
              >
                Learn more about OWASP LLM Top 10
              </a>
            </div>
          </div>
          
          {/* Call to Action Button */}
          <div className="pt-4 flex justify-center">
            <a href="https://www.straiker.ai/" target="_blank" rel="noopener noreferrer">
              <Button className="bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 shadow-lg">
                Is Your AI Secure? Find Out with a Free AI Risk Assessment
              </Button>
            </a>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default RemediationSuggestionsCard;
