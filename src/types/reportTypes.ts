
export interface OwaspCategory {
  id: string;
  name: string;
  description: string;
}

export interface AIComponent {
  name: string;
  type: string;
  confidence: number;
}

export interface SecurityRisk {
  risk: string;
  severity: string;
  description: string;
  related_code_references: string[]; // IDs of related code references
  owasp_category?: OwaspCategory; // OWASP LLM Top 10 category
}

export interface CodeReference {
  id: string; // Unique ID for each reference
  file: string;
  line: number;
  snippet: string;
  verified: boolean;
  relatedRisks?: string[]; // Risk names this reference is related to
}

export interface RemediationSuggestion {
  suggestion: string;
  [key: string]: any; // Allow for any other properties
}

export interface RepositoryReport {
  ai_components_detected: AIComponent[];
  security_risks: SecurityRisk[];
  code_references: CodeReference[];
  confidence_score: number;
  remediation_suggestions: (RemediationSuggestion | string | null)[];
}
