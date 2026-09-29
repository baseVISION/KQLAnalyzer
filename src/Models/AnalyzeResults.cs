using System.Text.Json.Serialization;
using Kusto.Language;

public class AnalyzeResults
{
    public AnalyzeResults()
    {
        this.OutputColumns = new Dictionary<string, string>();
        this.ParsingErrors = new List<Diagnostic>();
        this.ElapsedMs = 0;
        this.ReferencedTables = new List<string>();
        this.ReferencedFunctions = new List<string>();
        this.ReferencedColumns = new List<string>();
        this.ReferencedColumnsByTable = new Dictionary<string, List<string>>();
        this.EventsByTable = new Dictionary<string, List<string>>();
    }

    [JsonPropertyName("output_columns")]
    public Dictionary<string, string> OutputColumns { get; set; }

    [JsonPropertyName("parsing_errors")]
    public List<Diagnostic> ParsingErrors { get; set; }

    [JsonPropertyName("referenced_tables")]
    public List<string> ReferencedTables { get; set; }

    [JsonPropertyName("referenced_functions")]
    public List<string> ReferencedFunctions { get; set; }

    [JsonPropertyName("referenced_columns")]
    public List<string> ReferencedColumns { get; set; }

    [JsonPropertyName("referenced_columns_by_table")]
    public Dictionary<string, List<string>> ReferencedColumnsByTable { get; set; }

    // Event filters per table derived from equality/membership predicates on the
    // configured event columns (see event_columns.csv), formatted as "Column:Value"
    // (for example "ActionType:ProcessCreated"). Empty when no mapping is configured
    // or the query does not filter on a mapped event column.
    [JsonPropertyName("events_by_table")]
    public Dictionary<string, List<string>> EventsByTable { get; set; }

    [JsonPropertyName("elapsed_ms")]
    public long ElapsedMs { get; set; }
}
