using System.Collections.Generic;
using System.Text.Json;
using KQLAnalyzer;

public class Program
{
    /// <summary>
    /// KustoQueryAnalyzer can analyze a Kusto query and returns metadata about the query.
    /// </summary>
    /// <param name="inputFile">Analyze query from JSON file.</param>
    /// <param name="environmentsFile">Environment configuration file to use. Defaults to ../environments.json.</param>
    /// <param name="eventColumnsFile">Table to event column mapping CSV used for event filter extraction. Defaults to ../event_columns.csv.</param>
    /// <param name="rest">Start a REST server to listen for requests.</param>
    /// <param name="bindAddress">HTTP bind address to use in format http://host:port.</param>
#pragma warning disable 8625
    public static void Main(
        FileInfo inputFile = null,
        FileInfo environmentsFile = null,
        FileInfo eventColumnsFile = null,
        bool rest = false,
        string bindAddress = "http://localhost:8000"
    )
#pragma warning restore 8625
    {
        environmentsFile = environmentsFile ?? new FileInfo(Path.Join("..", "environments.json"));
        eventColumnsFile = eventColumnsFile ?? new FileInfo(Path.Join("..", "event_columns.csv"));
        var kqlEnvironments = new KQLEnvironments();
        try
        {
            kqlEnvironments = JsonSerializer.Deserialize<KQLEnvironments>(
                File.ReadAllText(environmentsFile.FullName)
            )!;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Could not parse environments file {environmentsFile.FullName}: {e.Message}");
            Environment.Exit(1);
        }

        // Normalize schema names from documentation artifacts (for example
        // markdown-suffixed columns like GroupMembership[**](#sentinel)).
        EnvironmentUtils.NormalizeEnvironmentDefinitions(kqlEnvironments);

        // Add merged m365_with_sentinel environment if both m365 and sentinel exist
        EnvironmentUtils.AddM365WithSentinelIfPresent(kqlEnvironments);

        var eventColumnsByTable = EventColumnMapping.Load(eventColumnsFile);
        if (eventColumnsByTable.Count > 0)
        {
            Console.WriteLine(
                $"Loaded event column mapping for {eventColumnsByTable.Count} tables from {eventColumnsFile.FullName}"
            );
        }
        else
        {
            Console.WriteLine(
                $"No event column mapping loaded from {eventColumnsFile.FullName}; events_by_table will be empty."
            );
        }

        if (rest)
        {
            KQLAnalyzerRESTService.LaunchRestServer(bindAddress, kqlEnvironments, eventColumnsByTable);
            return;
        }

        if (inputFile != null)
        {
            var analyzeRequest = new AnalyzeRequest();
            try
            {
                analyzeRequest = JsonSerializer.Deserialize<AnalyzeRequest>(
                    File.ReadAllText(inputFile.FullName)
                )!;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Could not parse input file {inputFile.FullName}: {e.Message}");
                Environment.Exit(1);
            }

            var environmentName = analyzeRequest.Environment;
            if (!kqlEnvironments.TryGetValue(environmentName, out var environment))
            {
                Console.WriteLine($"Could not find environment {environmentName}.");
                Environment.Exit(1);
            }

            var results = KustoAnalyzer.AnalyzeQuery(
                analyzeRequest.Query,
                environment.ToGlobalState(),
                analyzeRequest.LocalData,
                eventColumnsByTable
            );
            Console.WriteLine(
                JsonSerializer.Serialize(
                    results,
                    new JsonSerializerOptions { WriteIndented = true }
                )
            );
            return;
        }

        Console.WriteLine("Please provide either --input-file or --rest.");
        Environment.Exit(1);
    }
}
