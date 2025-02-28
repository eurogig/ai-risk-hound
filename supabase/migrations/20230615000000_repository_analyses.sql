
CREATE TABLE IF NOT EXISTS repository_analyses (
  id BIGSERIAL PRIMARY KEY,
  repository_url TEXT NOT NULL,
  analysis_result JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create an index on the repository_url for faster lookups
CREATE INDEX IF NOT EXISTS repository_analyses_url_idx ON repository_analyses (repository_url);

-- Add RLS policies
ALTER TABLE repository_analyses ENABLE ROW LEVEL SECURITY;

-- Allow anonymous users to view analyses
CREATE POLICY "Allow anonymous read access" 
ON repository_analyses FOR SELECT USING (true);

-- Only allow authenticated users to insert analyses
CREATE POLICY "Allow authenticated users to insert analyses" 
ON repository_analyses FOR INSERT TO authenticated USING (true);
