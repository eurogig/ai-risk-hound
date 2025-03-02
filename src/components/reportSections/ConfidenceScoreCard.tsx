import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

interface ConfidenceScoreCardProps {
  components: Array<{
    name: string;
    type: string;
    confidence: number;
    detectionMethod: string;
  }>;
}

interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'destructive';
  className?: string;
}

const ConfidenceScoreCard = ({ components }: ConfidenceScoreCardProps) => {
  // Handle empty components array
  if (!components || components.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">AI Confidence Score</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">No AI components detected</span>
              <span className="font-medium">0%</span>
            </div>
            <Progress value={0} className="h-2 bg-gray-100" />
            <div className="pt-2">
              <Badge className="bg-green-500">No AI Usage Detected</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Update the confidence score calculation
  const confidenceScore = components.length > 0 
    ? Math.round(Math.max(...components.map(c => c.confidence)) * 100)
    : 0;

  // Update the badge color based on confidence
  const getBadgeColor = (score: number) => {
    if (score > 80) return "bg-red-500";
    if (score > 40) return "bg-yellow-500";
    return "bg-green-500";
  };

  // Update the badge text
  const getBadgeText = (score: number) => {
    if (score > 80) return "High AI Usage";
    if (score > 40) return "Moderate AI Usage";
    return "Low/No AI Usage";
  };

  // Original rendering logic for when we have components
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">AI Confidence Score</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-500">How likely this repo contains AI components</span>
            <span className="font-medium">{confidenceScore}%</span>
          </div>
          <Progress 
            value={confidenceScore} 
            className={`h-2 ${confidenceScore > 0.7 ? 'bg-red-100' : 'bg-gray-100'}`} 
          />
          <div className="pt-2">
            <Badge className={getBadgeColor(confidenceScore)}>
              {getBadgeText(confidenceScore)}
            </Badge>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ConfidenceScoreCard;
