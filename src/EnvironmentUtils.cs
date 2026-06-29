using System.Collections.Generic;
using System.Text.RegularExpressions;
using KQLAnalyzer;

public static class EnvironmentUtils
{
    private static readonly Regex MarkdownSuffixRegex = new(@"\[\*\*\]\(#.*\)$", RegexOptions.Compiled);

    private static string NormalizeSchemaName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        return MarkdownSuffixRegex.Replace(name, string.Empty).Trim();
    }

    public static void NormalizeEnvironmentDefinitions(IDictionary<string, EnvironmentDefinition> kqlEnvironments)
    {
        foreach (var envKey in kqlEnvironments.Keys.ToList())
        {
            var environment = kqlEnvironments[envKey];
            var normalizedTables = new Dictionary<string, TableDetails>(StringComparer.OrdinalIgnoreCase);

            foreach (var tableEntry in environment.TableDetails)
            {
                var normalizedTableName = NormalizeSchemaName(tableEntry.Key);
                if (string.IsNullOrWhiteSpace(normalizedTableName))
                {
                    continue;
                }

                if (!normalizedTables.TryGetValue(normalizedTableName, out var normalizedColumns))
                {
                    normalizedColumns = new TableDetails();
                    normalizedTables[normalizedTableName] = normalizedColumns;
                }

                foreach (var columnEntry in tableEntry.Value)
                {
                    var normalizedColumnName = NormalizeSchemaName(columnEntry.Key);
                    if (string.IsNullOrWhiteSpace(normalizedColumnName))
                    {
                        continue;
                    }

                    if (!normalizedColumns.ContainsKey(normalizedColumnName))
                    {
                        normalizedColumns[normalizedColumnName] = columnEntry.Value;
                    }
                }
            }

            environment.TableDetails = normalizedTables;
            kqlEnvironments[envKey] = environment;
        }
    }

    /// <summary>
    /// If both m365 and sentinel environments exist, create a merged environment m365_with_sentinel.
    /// Adds the merged environment to the dictionary if applicable.
    /// </summary>
    /// <param name="kqlEnvironments">The environments dictionary to update.</param>
    public static void AddM365WithSentinelIfPresent(IDictionary<string, EnvironmentDefinition> kqlEnvironments)
    {
        if (kqlEnvironments.ContainsKey("m365") && kqlEnvironments.ContainsKey("sentinel"))
        {
            var m365 = kqlEnvironments["m365"];
            var sentinel = kqlEnvironments["sentinel"];

            var mergedMagicFunctions = new HashSet<string>(m365.MagicFunctions, StringComparer.OrdinalIgnoreCase);
            foreach (var fn in sentinel.MagicFunctions)
            {
                mergedMagicFunctions.Add(fn);
            }

            var merged = new EnvironmentDefinition
            {
                TableDetails = new Dictionary<string, TableDetails>(StringComparer.OrdinalIgnoreCase),
                MagicFunctions = mergedMagicFunctions.ToList()
            };

            // Deep copy tables from m365
            foreach (var tableEntry in m365.TableDetails)
            {
                var copiedTableDetails = new TableDetails();
                foreach (var columnEntry in tableEntry.Value)
                {
                    copiedTableDetails[columnEntry.Key] = columnEntry.Value;
                }

                merged.TableDetails[tableEntry.Key] = copiedTableDetails;
            }

            // Add tables from sentinel if not already present (no overwrite)
            foreach (var tableEntry in sentinel.TableDetails)
            {
                if (!merged.TableDetails.ContainsKey(tableEntry.Key))
                {
                    var copiedTableDetails = new TableDetails();
                    foreach (var columnEntry in tableEntry.Value)
                    {
                        copiedTableDetails[columnEntry.Key] = columnEntry.Value;
                    }

                    merged.TableDetails[tableEntry.Key] = copiedTableDetails;
                }
                else
                {
                    // Keep m365 as canonical for overlapping tables but append missing
                    // columns from Sentinel to reduce false negatives on mixed content.
                    var existingColumns = merged.TableDetails[tableEntry.Key];
                    foreach (var columnEntry in tableEntry.Value)
                    {
                        if (!existingColumns.ContainsKey(columnEntry.Key))
                        {
                            existingColumns[columnEntry.Key] = columnEntry.Value;
                        }
                    }
                }
            }

            kqlEnvironments["m365_with_sentinel"] = merged;
        }
    }
}