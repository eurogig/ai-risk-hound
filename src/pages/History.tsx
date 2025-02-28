
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import ReportResults from "@/components/ReportResults";
import Navigation from "@/components/Navigation";
import { supabase } from "@/integrations/supabase/client";

interface AnalysisRecord {
  id: number;
  repository_url: string;
  analysis_result: any;
  created_at: string;
}

const History = () => {
  const [analyses, setAnalyses] = useState<AnalysisRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AnalysisRecord | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    const fetchAnalyses = async () => {
      try {
        setIsLoading(true);
        
        // Fetch analyses from Supabase database
        const { data, error } = await supabase
          .from('repository_analyses')
          .select('*')
          .order('created_at', { ascending: false });
        
        if (error) {
          throw error;
        }

        setAnalyses(data || []);
        
        // Auto-select the first analysis if available
        if (data && data.length > 0) {
          setSelectedAnalysis(data[0]);
        }
      } catch (err) {
        console.error('Error fetching analyses:', err);
        toast({
          title: "Error",
          description: "Failed to load analysis history",
          variant: "destructive",
        });
      } finally {
        setIsLoading(false);
      }
    };

    fetchAnalyses();
  }, [toast]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 flex flex-col">
      <Navigation />
      <div className="flex-1 p-6">
        <div className="max-w-6xl mx-auto">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">Analysis History</h1>
          </div>

          {isLoading ? (
            <div className="flex justify-center items-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-gray-500" />
            </div>
          ) : analyses.length === 0 ? (
            <Card>
              <CardContent className="p-6">
                <p className="text-center text-gray-500">No analysis history found</p>
                <div className="mt-4 text-center">
                  <Button onClick={() => window.location.href = "/"}>
                    Analyze a Repository
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-1">
                <Card className="sticky top-6">
                  <CardHeader>
                    <CardTitle>Recent Analyses</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 max-h-[70vh] overflow-y-auto">
                    {analyses.map((analysis) => (
                      <div
                        key={analysis.id}
                        className={`p-3 rounded-md cursor-pointer transition-colors ${
                          selectedAnalysis?.id === analysis.id
                            ? "bg-primary text-primary-foreground"
                            : "bg-gray-100 hover:bg-gray-200"
                        }`}
                        onClick={() => setSelectedAnalysis(analysis)}
                      >
                        <p className="font-medium truncate">{analysis.repository_url}</p>
                        <p className="text-sm opacity-80">{formatDate(analysis.created_at)}</p>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </div>

              <div className="md:col-span-2">
                {selectedAnalysis ? (
                  <div className="space-y-4">
                    <Card className="bg-white">
                      <CardHeader>
                        <CardTitle className="break-all">
                          {selectedAnalysis.repository_url}
                        </CardTitle>
                        <p className="text-sm text-gray-500">
                          Analyzed on {formatDate(selectedAnalysis.created_at)}
                        </p>
                      </CardHeader>
                    </Card>
                    <ReportResults report={selectedAnalysis.analysis_result} />
                  </div>
                ) : (
                  <Card className="h-64 flex items-center justify-center">
                    <p className="text-gray-500">Select an analysis to view details</p>
                  </Card>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default History;
