// This file is automatically generated. Do not edit it directly.
import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

const SUPABASE_URL = "https://bnmbrtsyqxqoitrcesgu.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJubWJydHN5cXhxb2l0cmNlc2d1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDA3MDEyNDgsImV4cCI6MjA1NjI3NzI0OH0.PT-jorVmwDQIG0iKQ5bI2nCEClMxkoBv8yfRdu9-7XA";

// Import the supabase client like this:
// import { supabase } from "@/integrations/supabase/client";

export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);