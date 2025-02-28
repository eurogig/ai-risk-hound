
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

interface ConfidenceScoreCardProps {
  confidenceScore: number;
}

const ConfidenceScoreCard = ({ confidenceScore }: ConfidenceScoreCardProps) => {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xl">AI Confidence Score</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-500">How likely this repo contains AI components</span>
            <span className="font-medium">{Math.round(confidenceScore * 100)}%</span>
          </div>
          <Progress 
            value={confidenceScore * 100} 
            className={`h-2 ${confidenceScore > 0.7 ? 'bg-red-100' : 'bg-gray-100'}`} 
          />
          <div className="pt-2">
            {confidenceScore > 0.8 ? (
              <Badge className="bg-red-500">High AI Usage</Badge>
            ) : confidenceScore > 0.4 ? (
              <Badge className="bg-yellow-500">Moderate AI Usage</Badge>
            ) : (
              <Badge className="bg-green-500">Low/No AI Usage</Badge>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ConfidenceScoreCard;
