
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeReference } from "@/types/reportTypes";
import CodeReferencesList from "./CodeReferencesList";

interface AdditionalCodeReferencesCardProps {
  references: CodeReference[];
}

const AdditionalCodeReferencesCard = ({ references }: AdditionalCodeReferencesCardProps) => {
  if (references.length === 0) {
    return null;
  }
  
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">Additional AI References in Code</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-500 mb-3">
          These code references show AI implementations not directly associated with any detected security risks.
        </p>
        <CodeReferencesList references={references} />
      </CardContent>
    </Card>
  );
};

export default AdditionalCodeReferencesCard;
