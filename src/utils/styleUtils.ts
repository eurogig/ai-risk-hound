
// Get severity color based on risk severity level
export const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-yellow-500";
    case "low":
      return "bg-blue-500";
    case "info":
      return "bg-gray-500";
    default:
      return "bg-gray-500";
  }
};

// Get OWASP badge color based on category ID
export const getOwaspBadgeColor = (categoryId: string) => {
  switch (categoryId) {
    case "LLM01":
      return "bg-red-700 hover:bg-red-800";
    case "LLM02":
      return "bg-orange-700 hover:bg-orange-800";
    case "LLM03":
      return "bg-yellow-700 hover:bg-yellow-800";
    case "LLM04":
      return "bg-amber-700 hover:bg-amber-800";
    case "LLM05":
      return "bg-indigo-700 hover:bg-indigo-800";
    case "LLM06":
      return "bg-purple-700 hover:bg-purple-800";
    case "LLM07":
      return "bg-blue-700 hover:bg-blue-800";
    case "LLM08":
      return "bg-cyan-700 hover:bg-cyan-800";
    case "LLM09":
      return "bg-teal-700 hover:bg-teal-800";
    case "LLM10":
      return "bg-emerald-700 hover:bg-emerald-800";
    default:
      return "bg-gray-700 hover:bg-gray-800";
  }
};
