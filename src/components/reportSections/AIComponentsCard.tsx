
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AIComponent } from "@/types/reportTypes";

interface AIComponentsCardProps {
  components: AIComponent[];
}

const AIComponentsCard = ({ components }: AIComponentsCardProps) => {
  if (components.length === 0) {
    return null;
  }
  
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">AI Components Detected</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {components.map((component, index) => (
            <div key={index} className="flex justify-between items-center p-3 rounded-md bg-gray-50">
              <div>
                <div className="font-medium">{component.name}</div>
                <div className="text-sm text-gray-500">{component.type}</div>
              </div>
              <Badge variant="outline" className="ml-auto">
                {Math.round(component.confidence * 100)}% confidence
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default AIComponentsCard;
