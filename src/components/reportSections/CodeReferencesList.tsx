
import { 
  Accordion, 
  AccordionContent, 
  AccordionItem, 
  AccordionTrigger 
} from "@/components/ui/accordion";
import { CodeReference } from "@/types/reportTypes";

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
            <div className="flex items-center text-left">
              <span className="font-medium">{reference.file}</span>
              <span className="ml-2 text-sm text-gray-500">Line {reference.line}</span>
            </div>
          </AccordionTrigger>
          <AccordionContent>
            <div className="p-3 rounded-md font-mono text-sm overflow-x-auto bg-gray-100">
              {reference.snippet}
            </div>
          </AccordionContent>
        </AccordionItem>
      ))}
    </Accordion>
  );
};

export default CodeReferencesList;
