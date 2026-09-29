using System.Text.Json;
using KQLAnalyzer;
using Xunit;

public class AnalyzeQueryTests
{
    private static readonly KQLEnvironments kqlEnvironments = LoadEnvironments();

    private static KQLEnvironments LoadEnvironments()
    {
        // environments.json is copied to the test output directory by the csproj.
        var environments = JsonSerializer.Deserialize<KQLEnvironments>(
            File.ReadAllText("environments.json")
        )!;
        EnvironmentUtils.NormalizeEnvironmentDefinitions(environments);
        EnvironmentUtils.AddM365WithSentinelIfPresent(environments);
        return environments;
    }

    private static AnalyzeResults AnalyzeFromJson(
        string path,
        IReadOnlyDictionary<string, IReadOnlyList<string>> eventColumnsByTable = null
    )
    {
        var request = JsonSerializer.Deserialize<AnalyzeRequest>(File.ReadAllText(path))!;
        var globals = kqlEnvironments[request.Environment].ToGlobalState();
        return KustoAnalyzer.AnalyzeQuery(
            request.Query,
            globals,
            request.LocalData,
            eventColumnsByTable
        );
    }

    [Fact]
    public void TabularFunctionWithMissingRequiredArgument()
    {
        var results = AnalyzeFromJson("test_data/tabular_function_required_args.json");
        Assert.Contains(results.ParsingErrors, (e => e.Code == "KS119")); // Expect KS119 error The function 'MyFunction' expects 1 argument.
    }

    [Fact]
    public void ScalarFunction()
    {
        var results = AnalyzeFromJson("test_data/scalar_function.json");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(results.OutputColumns, new Dictionary<string, string> { { "a", "bool" } });
        Assert.Equal(results.ReferencedFunctions, new List<string> { "MyScalar" });
    }

    [Fact]
    public void Watchlist()
    {
        var results = AnalyzeFromJson("test_data/watchlist.json");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            results.OutputColumns,
            new Dictionary<string, string>
            {
                { "_DTItemId", "string" },
                { "LastUpdatedTimeUTC", "datetime" },
                { "SearchKey", "string" },
                { "WatchlistItem", "dynamic" },
                { "foo", "string" },
            }
        );
        Assert.Equal(results.ReferencedFunctions, new List<string> { "_GetWatchlist" });
    }

    [Fact]
    public void ReplaceStringWithVerbatimBackslashAndEmptyDoubleQuotedLiteral()
    {
        var query = """print x = replace_string("abc", @"\", "")""";
        var globals = kqlEnvironments["sentinel"].ToGlobalState();
        var results = KustoAnalyzer.AnalyzeQuery(query, globals, null);
        Assert.Empty(results.ParsingErrors);
        Assert.Equal("string", results.OutputColumns["x"]);
    }

    [Fact]
    public void IifWithEmptyDoubleQuotedLiteralFollowedByExtend()
    {
        // Regression test for the ASIM WebSession rendered-query failures. The failing
        // shape is an iif() whose last argument is an empty double-quoted literal,
        // immediately followed by an appended test extend line. KQLAnalyzer
        // must normalize the empty literal and still parse the whole query.
        var query =
            "_Im_WebSession(starttime=ago(4h), endtime=now())\n"
            + "| extend Name = iif(SrcUsername contains \"@\", tostring(split(SrcUsername, '@', 0)[0]), SrcUsername), UPNSuffix = iif(SrcUsername contains \"@\", tostring(split(SrcUsername, '@', 1)[0]), \"\")\n"
            + "| extend test = strcat(\"test\")";
        var globals = kqlEnvironments["sentinel"].ToGlobalState();
        var results = KustoAnalyzer.AnalyzeQuery(query, globals, null);
        Assert.Empty(results.ParsingErrors);
        Assert.Equal("string", results.OutputColumns["UPNSuffix"]);
        Assert.Equal("string", results.OutputColumns["test"]);
    }

    // ------------------------------------------------------------------
    // Event filter extraction (events_by_table)
    // ------------------------------------------------------------------

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> EventColumns =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["DeviceProcessEvents"] = new List<string> { "ActionType" },
            ["DeviceFileEvents"] = new List<string> { "ActionType" },
            ["AuditLogs"] = new List<string> { "OperationName" },
        };

    private static AnalyzeResults AnalyzeWithEvents(string query, string environment = "m365")
    {
        var globals = kqlEnvironments[environment].ToGlobalState();
        return KustoAnalyzer.AnalyzeQuery(query, globals, null, EventColumns);
    }

    [Fact]
    public void EventFiltersEqualityOperator()
    {
        var results = AnalyzeWithEvents("DeviceProcessEvents | where ActionType == 'ProcessCreated'");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:ProcessCreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersInOperator()
    {
        var results = AnalyzeWithEvents(
            "DeviceProcessEvents | where ActionType in ('ProcessCreated', 'ProcessTerminated')"
        );
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:ProcessCreated", "ActionType:ProcessTerminated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersCaseInsensitiveEquality()
    {
        var results = AnalyzeWithEvents("DeviceProcessEvents | where ActionType =~ 'processcreated'");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:processcreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersReversedOperands()
    {
        var results = AnalyzeWithEvents("DeviceProcessEvents | where 'ProcessCreated' == ActionType");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:ProcessCreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersIgnoresNegations()
    {
        var results = AnalyzeWithEvents(
            "DeviceProcessEvents | where ActionType != 'ProcessCreated' and ActionType !in ('X')"
        );
        Assert.Empty(results.EventsByTable);
    }

    [Fact]
    public void EventFiltersIgnoresUnmappedColumns()
    {
        var results = AnalyzeWithEvents("DeviceProcessEvents | where ProcessCommandLine == 'x.exe'");
        Assert.Empty(results.EventsByTable);
    }

    [Fact]
    public void EventFiltersUnwrapsScalarWrappers()
    {
        var results = AnalyzeWithEvents(
            "DeviceProcessEvents | where tolower(tostring(ActionType)) == 'processcreated'"
        );
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:processcreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersUsesCanonicalColumnCasingFromMapping()
    {
        var results = AnalyzeWithEvents("DeviceProcessEvents | where actiontype == 'ProcessCreated'");
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "ActionType:ProcessCreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersSentinelTable()
    {
        var results = AnalyzeWithEvents(
            "AuditLogs | where OperationName == 'Add user'",
            environment: "sentinel"
        );
        Assert.Empty(results.ParsingErrors);
        Assert.Equal(
            new List<string> { "OperationName:Add user" },
            results.EventsByTable["AuditLogs"]
        );
    }

    [Fact]
    public void EventFiltersAttributesSingleMappedTableByNameAfterProject()
    {
        // After project the column symbol no longer resolves to the database table;
        // the fallback attributes the filter because exactly one referenced table
        // maps the ActionType event column.
        var results = AnalyzeWithEvents(
            "DeviceProcessEvents | project ActionType, ProcessCommandLine | where ActionType == 'ProcessCreated'"
        );
        Assert.Equal(
            new List<string> { "ActionType:ProcessCreated" },
            results.EventsByTable["DeviceProcessEvents"]
        );
    }

    [Fact]
    public void EventFiltersAmbiguousTablesAreSkipped()
    {
        // Both referenced tables map ActionType, so a name-only reference cannot
        // be attributed unambiguously.
        var results = AnalyzeWithEvents(
            "union DeviceProcessEvents, DeviceFileEvents | where ActionType == 'ProcessCreated'"
        );
        Assert.Empty(results.EventsByTable);
    }

    [Fact]
    public void EventFiltersEmptyWithoutMapping()
    {
        var globals = kqlEnvironments["m365"].ToGlobalState();
        var results = KustoAnalyzer.AnalyzeQuery(
            "DeviceProcessEvents | where ActionType == 'ProcessCreated'",
            globals,
            null
        );
        Assert.Empty(results.EventsByTable);
    }

    [Fact]
    public void EventColumnMappingLoadParsesCsv()
    {
        var path = Path.Combine(Path.GetTempPath(), $"event_columns_{Guid.NewGuid():N}.csv");
        try
        {
            File.WriteAllLines(
                path,
                new[]
                {
                    "# comment line",
                    "Table,EventColumn",
                    "DeviceProcessEvents,ActionType",
                    "deviceprocessevents,ActionType",
                    "AuditLogs,OperationName",
                    "",
                }
            );

            var mapping = EventColumnMapping.Load(new FileInfo(path));

            Assert.Equal(2, mapping.Count);
            Assert.Equal(new List<string> { "ActionType" }, mapping["DeviceProcessEvents"]);
            Assert.Equal(new List<string> { "OperationName" }, mapping["AuditLogs"]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void EventColumnMappingLoadMissingFileReturnsEmpty()
    {
        var mapping = EventColumnMapping.Load(
            new FileInfo(Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.csv"))
        );
        Assert.Empty(mapping);
    }
}
