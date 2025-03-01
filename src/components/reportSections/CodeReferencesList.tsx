
import React from "react";
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from "@/components/ui/accordion";
import { CodeReference } from "@/types/reportTypes";
import { FileCode, Code } from "lucide-react";

interface CodeReferencesListProps {
  references: CodeReference[];
  riskIndex?: number;
}

const CodeReferencesList = ({ references, riskIndex }: CodeReferencesListProps) => {
  return (
    <Accordion type="single" collapsible className="w-full">
      {references.map((reference, refIndex) => (
        <AccordionItem 
          key={refIndex} 
          value={riskIndex ? `risk-${riskIndex}-ref-${refIndex}` : `ref-${refIndex}`} 
          className="border border-gray-100 rounded-md mb-2"
        >
          <AccordionTrigger className="hover:no-underline text-sm px-3 py-2">
            <div className="flex items-center text-left gap-2">
              <FileCode className="h-4 w-4 text-gray-500" />
              <span className="font-medium">{reference.file}</span>
              <span className="ml-2 text-sm text-gray-500">Line {reference.line}</span>
              {reference.type && (
                <span className="ml-auto text-xs bg-gray-100 px-2 py-0.5 rounded">
                  {formatReferenceType(reference.type)}
                </span>
              )}
            </div>
          </AccordionTrigger>
          <AccordionContent>
            <div className="p-3 space-y-3">
              {/* If context is available, show it with highlighted snippet */}
              {reference.context ? (
                <div className="rounded-md font-mono text-sm overflow-x-auto bg-gray-50 p-3">
                  <pre className="whitespace-pre-wrap">{highlightSnippetInContext(reference.context, reference.snippet)}</pre>
                </div>
              ) : (
                <div className="rounded-md font-mono text-sm overflow-x-auto bg-gray-50 p-3">
                  <pre className="whitespace-pre-wrap">{reference.snippet}</pre>
                </div>
              )}
              
              {/* Display additional information if available */}
              {reference.type && (
                <div className="flex items-center gap-2 text-xs text-gray-600 mt-2">
                  <Code className="h-3.5 w-3.5" />
                  <span>Identified as: <span className="font-medium">{formatReferenceType(reference.type)}</span></span>
                </div>
              )}

              {reference.confidence && (
                <div className="text-xs text-gray-600">
                  Detection confidence: {Math.round(reference.confidence * 100)}%
                </div>
              )}
            </div>
          </AccordionContent>
        </AccordionItem>
      ))}
    </Accordion>
  );
};

// Helper to highlight the snippet within the context
function highlightSnippetInContext(context: string, snippet: string): React.ReactNode {
  if (!snippet || !context) return context;
  
  try {
    // Simple approach: split by the snippet and join with a highlighted version
    const parts = context.split(snippet);
    
    if (parts.length <= 1) return context; // Snippet not found in context
    
    // Return context with highlighted snippet
    return (
      <>
        {parts.map((part, i) => (
          <React.Fragment key={i}>
            {part}
            {i < parts.length - 1 && (
              <span className="bg-yellow-200 px-0.5 -mx-0.5 rounded">{snippet}</span>
            )}
          </React.Fragment>
        ))}
      </>
    );
  } catch (e) {
    console.error("Error highlighting snippet:", e);
    return context;
  }
}

// Format the reference type for display
function formatReferenceType(type: string): string {
  // Convert snake_case to Title Case with spaces
  return type
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

export default CodeReferencesList;
