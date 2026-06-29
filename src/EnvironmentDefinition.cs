using System.Text.Json;
using System.Text.Json.Serialization;
using Kusto.Language;
using Kusto.Language.Symbols;

public class EnvironmentDefinition
{
    // -------------------------------------------------------------------------
    // Magic functions (M365-specific, gated on magic_functions list)
    // -------------------------------------------------------------------------

    private static readonly FunctionSymbol FileProfileFunction =
        // Copies all the columns from the existing table and adds the new ones as specified by Microsoft.
        // The join is there to get the same behavior as the FileProfile function where if a column
        // named GlobalPrevalence or any other output column is already present in the table,
        // it will not be overwritten but a new column called GlobalPrevalence1 will be added.
        new (
            "FileProfile",
            "(T:(*), x:string='',y:string='')",
            """
            {
                (T | extend _TmpJoinKey=123)
                | join (
                    print SHA1='', SHA256='', MD5='', FileSize=0, GlobalPrevalence=0, GlobalFirstSeen=now(),
                    GlobalLastSeen=now(), Signer='', Issuer='', SignerHash='', IsCertificateValid=false,
                    IsRootSignerMicrosoft=false, SignatureState='', IsExecutable=false, ThreatName='',
                    Publisher='', SoftwareName='', ProfileAvailability='',_TmpJoinKey=123
                ) on _TmpJoinKey | project-away _TmpJoinKey, _TmpJoinKey1
            }
            """
        );

    private static readonly FunctionSymbol DeviceFromIPFunction =
        new (
            "DeviceFromIP",
            "(T:(*), x:string='',y:datetime='')",
            """
            {
                (T | extend _TmpJoinKey=123)
                | join (
                    print IP='', DeviceId='', _TmpJoinKey=123
                ) on _TmpJoinKey | project-away _TmpJoinKey, _TmpJoinKey1
            }
            """
        );

    // -------------------------------------------------------------------------
    // Built-in scalar helpers (always available)
    // -------------------------------------------------------------------------

    private static readonly FunctionSymbol Ipv4RangeToCidrListFunction = new(
        "ipv4_range_to_cidr_list",
        ScalarTypes.Dynamic,
        new Parameter("startip", ScalarTypes.String),
        new Parameter("endip", ScalarTypes.String)
    );

    private static readonly FunctionSymbol Ipv4IsPrivateFunction = new(
        "ipv4_is_private",
        ScalarTypes.Bool,
        new Parameter("ip", ScalarTypes.String)
    );

    // Compatibility overload for environments/Kusto language versions where
    // extract(pattern, captureGroup, source) may otherwise resolve to a 4-arg-only signature.
    private static readonly FunctionSymbol ExtractFunction3 = new(
        "extract",
        ScalarTypes.String,
        new Parameter("regex", ScalarTypes.String),
        new Parameter("captureGroup", ScalarTypes.Int),
        new Parameter("source", ScalarTypes.String)
    );

    private static readonly FunctionSymbol SplitFunction2 = new(
        "split",
        ScalarTypes.Dynamic,
        new Parameter("source", ScalarTypes.String),
        new Parameter("delimiter", ScalarTypes.String)
    );

    private static readonly FunctionSymbol ExtractFunction4 = new(
        "extract",
        ScalarTypes.String,
        new Parameter("regex", ScalarTypes.String),
        new Parameter("captureGroup", ScalarTypes.Int),
        new Parameter("source", ScalarTypes.String),
        new Parameter("typeLiteral", ScalarTypes.Type)
    );

    // -------------------------------------------------------------------------
    // ASIM parser function groups (always available, schema resolved from environment tables)
    //
    // Each group declares:
    //   Names       – the three ASIM function variants (_Im_X, _Im_X_Native, _ASim_X)
    //   Table       – the backing ASimXxxLogs table whose columns form the return schema
    //   Extra       – additional columns the stubs add via extend (only added when absent)
    //   Params      – optional filter parameters accepted by all variants
    // -------------------------------------------------------------------------

    private static readonly (string[] Names, string Table, Dictionary<string, string> Extra, (string Name, TypeSymbol Type)[] Params)[] AsimGroups =
    [
        (
            ["_Im_AuditEvent", "_Im_AuditEvent_Native", "_ASim_AuditEvent"],
            "ASimAuditEventLogs",
            new() { ["Dvc"] = "string" },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("eventtype_in", ScalarTypes.Dynamic),
                ("eventresult", ScalarTypes.String), ("actorusername_has_any", ScalarTypes.Dynamic),
                ("operation_has_any", ScalarTypes.Dynamic), ("object_has_any", ScalarTypes.Dynamic),
                ("newvalue_has_any", ScalarTypes.Dynamic)
            ]
        ),
        (
            ["_Im_Authentication", "_Im_Authentication_Native", "_ASim_Authentication"],
            "ASimAuthenticationEventLogs",
            new() { ["AuthenticationDetails"] = "string" },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("targetusername_has", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_DhcpEvent", "_Im_DhcpEvent_Native", "_ASim_DhcpEvent"],
            "ASimDhcpEventLogs",
            new(),
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("srchostname_has_any", ScalarTypes.Dynamic),
                ("srcusername_has_any", ScalarTypes.Dynamic), ("eventresult", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_Dns", "_Im_Dns_Native", "_ASim_Dns"],
            "ASimDnsActivityLogs",
            new(),
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr", ScalarTypes.String), ("domain_has_any", ScalarTypes.Dynamic),
                ("responsecodename", ScalarTypes.String), ("response_has_ipv4", ScalarTypes.String),
                ("response_has_any_prefix", ScalarTypes.Dynamic), ("eventtype", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_FileEvent", "_Im_FileEvent_Native", "_ASim_FileEvent"],
            "ASimFileEventLogs",
            new() { ["ActingProcessParentFileName"] = "string", ["TargetUserId"] = "string", ["AccountName"] = "string", ["TargetProcessName"] = "string", ["User"] = "string", ["CommandLine"] = "string", ["Dvc"] = "string", ["DvcId"] = "string" },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("eventtype_in", ScalarTypes.Dynamic), ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic),
                ("actorusername_has_any", ScalarTypes.Dynamic), ("targetfilepath_has_any", ScalarTypes.Dynamic),
                ("srcfilepath_has_any", ScalarTypes.Dynamic), ("hashes_has_any", ScalarTypes.Dynamic),
                ("dvchostname_has_any", ScalarTypes.Dynamic), ("ActingProcessParentFileName", ScalarTypes.String),
                ("AccountName", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_NetworkSession", "_Im_NetworkSession_Native", "_ASim_NetworkSession"],
            "ASimNetworkSessionLogs",
            new()
            {
                ["SrcProcessIntegrityLevel"] = "string",
                ["InitiatingProcessVersionInfoOriginalFileName"] = "string",
                ["InitiatingProcessVersionInfoFileDescription"] = "string",
                ["SrcProcessName"] = "string",
                ["ParentProcessName"] = "string",
                ["InitiatingProcessParentId"] = "long",
                ["InitiatingProcessId"] = "long"
            },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("dstipaddr_has_any_prefix", ScalarTypes.Dynamic),
                ("ipaddr_has_any_prefix", ScalarTypes.Dynamic), ("dstportnumber", ScalarTypes.Int),
                ("hostname_has_any", ScalarTypes.Dynamic), ("dvcaction", ScalarTypes.Dynamic),
                ("eventresult", ScalarTypes.String), ("SrcProcessIntegrityLevel", ScalarTypes.String),
                ("InitiatingProcessVersionInfoOriginalFileName", ScalarTypes.String),
                ("SrcProcessName", ScalarTypes.String),
                ("ParentProcessName", ScalarTypes.String),
                ("InitiatingProcessParentId", ScalarTypes.Long),
                ("InitiatingProcessId", ScalarTypes.Long)
            ]
        ),
        (
            ["_Im_ProcessEvent", "_Im_ProcessEvent_Native", "_ASim_ProcessEvent"],
            "ASimProcessEventLogs",
            new() { ["CommandLine"] = "string", ["Dvc"] = "string", ["DeviceId"] = "string", ["Process"] = "string", ["Hash"] = "string" },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("commandline_has_any", ScalarTypes.Dynamic), ("commandline_has_all", ScalarTypes.Dynamic),
                ("commandline_has_any_ip_prefix", ScalarTypes.Dynamic), ("actingprocess_has_any", ScalarTypes.Dynamic),
                ("targetprocess_has_any", ScalarTypes.Dynamic), ("parentprocess_has_any", ScalarTypes.Dynamic),
                ("targetusername_has", ScalarTypes.String), ("actorusername_has", ScalarTypes.String),
                ("dvcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("dvchostname_has_any", ScalarTypes.Dynamic),
                ("eventtype", ScalarTypes.String), ("CommandLine", ScalarTypes.String),
                ("Dvc", ScalarTypes.String), ("DeviceId", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_RegistryEvent", "_Im_RegistryEvent_Native", "_ASim_RegistryEvent"],
            "ASimRegistryEventLogs",
            new()
            {
                ["ActingProcessMD5"] = "string", ["ActingProcessSHA1"] = "string",
                ["ActingProcessSHA256"] = "string", ["RegistryValueName"] = "string",
                ["Dvc"] = "string", ["DvcId"] = "string", ["EventStartTime"] = "datetime",
                ["RegistryValue"] = "string", ["ActingProcessCommandLine"] = "string",
                ["ActionType"] = "string", ["Type"] = "string"
            },
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("eventtype_in", ScalarTypes.Dynamic), ("actorusername_has_any", ScalarTypes.Dynamic),
                ("registrykey_has_any", ScalarTypes.Dynamic), ("registryvalue_has_any", ScalarTypes.Dynamic),
                ("registrydata_has_any", ScalarTypes.Dynamic), ("dvchostname_has_any", ScalarTypes.Dynamic),
                ("ActingProcessMD5", ScalarTypes.String), ("RegistryValueName", ScalarTypes.String)
            ]
        ),
        (
            ["_Im_UserManagement", "_Im_UserManagement_Native", "_ASim_UserManagement"],
            "ASimUserManagementActivityLogs",
            new(),
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("targetusername_has_any", ScalarTypes.Dynamic),
                ("actorusername_has_any", ScalarTypes.Dynamic), ("eventtype_in", ScalarTypes.Dynamic)
            ]
        ),
        (
            ["_Im_WebSession", "_Im_WebSession_Native", "_ASim_WebSession"],
            "ASimWebSessionLogs",
            new(),
            [
                ("starttime", ScalarTypes.DateTime), ("endtime", ScalarTypes.DateTime),
                ("srcipaddr_has_any_prefix", ScalarTypes.Dynamic), ("ipaddr_has_any_prefix", ScalarTypes.Dynamic),
                ("url_has_any", ScalarTypes.Dynamic), ("httpuseragent_has_any", ScalarTypes.Dynamic),
                ("eventresultdetails_in", ScalarTypes.Dynamic), ("eventresult", ScalarTypes.String)
            ]
        )
    ];

    public EnvironmentDefinition()
    {
        this.TableDetails = new Dictionary<string, TableDetails>();
        this.MagicFunctions = new List<string>();
    }

    [JsonPropertyName("tables")]
    public Dictionary<string, TableDetails> TableDetails { get; set; }

    [JsonPropertyName("magic_functions")]
    public List<string> MagicFunctions { get; set; }

    public GlobalState ToGlobalState()
    {
        List<Symbol> dbMembers = new List<Symbol>();

        // Build table symbols and keep the column instances so ASIM function symbols
        // can reuse them — this lets GetTable(column) resolve back to the source table,
        // enabling correct referenced_columns_by_table tracking.
        var tableColumnMap = new Dictionary<string, List<ColumnSymbol>>(StringComparer.OrdinalIgnoreCase);

        foreach (var table in this.TableDetails)
        {
            List<ColumnSymbol> columns = table.Value
                .Select(column =>
                {
                    if (ScalarTypes.GetSymbol(column.Value) == null)
                    {
                        throw new Exception(
                            $"Unknown type {column.Value} for column {column.Key} in table {table.Key}"
                        );
                    }

                    return new ColumnSymbol(column.Key, ScalarTypes.GetSymbol(column.Value));
                })
                .ToList();
            dbMembers.Add(new TableSymbol(table.Key, columns));
            tableColumnMap[table.Key] = columns;
        }

        if (this.MagicFunctions.Contains("FileProfile"))
        {
            dbMembers.Add(FileProfileFunction);
        }

        if (this.MagicFunctions.Contains("DeviceFromIP"))
        {
            dbMembers.Add(DeviceFromIPFunction);
        }

        // Always register ASIM parser functions and scalar helpers so queries
        // can reference them without requiring the PS client to prepend stubs.
        dbMembers.AddRange(BuildAsimFunctionSymbols(tableColumnMap));
        dbMembers.Add(Ipv4RangeToCidrListFunction);
        dbMembers.Add(Ipv4IsPrivateFunction);
        dbMembers.Add(ExtractFunction3);
        dbMembers.Add(ExtractFunction4);
        dbMembers.Add(SplitFunction2);

        return GlobalState.Default.WithDatabase(new DatabaseSymbol("db", dbMembers));
    }

    /// <summary>
    /// Builds one FunctionSymbol per ASIM parser name. Column symbols from the
    /// backing ASIM table are reused so GetTable(column) resolves correctly for
    /// referenced_columns_by_table tracking. Extra synthetic columns are new
    /// instances (they have no originating database table).
    /// </summary>
    private IEnumerable<FunctionSymbol> BuildAsimFunctionSymbols(
        Dictionary<string, List<ColumnSymbol>> tableColumnMap)
    {
        foreach (var (names, table, extra, paramDefs) in AsimGroups)
        {
            var cols = BuildAsimColumns(table, extra, tableColumnMap);
            var parameters = paramDefs
                .Select(p => new Parameter(p.Name, p.Type, minOccurring: 0))
                .ToArray();

            foreach (var name in names)
            {
                var capturedCols = cols;
                yield return new FunctionSymbol(
                    name,
                    context => new TableSymbol(capturedCols).WithInheritableProperties(context.RowScope),
                    Tabularity.Tabular,
                    parameters
                );
            }
        }
    }

    /// <summary>
    /// Returns the merged column list for an ASIM function.
    /// Columns from the backing ASIM table are the SAME ColumnSymbol instances
    /// registered in the database (so GetTable resolves them back to the table).
    /// Extra columns are new instances since they are synthetic parser additions.
    /// </summary>
    private static List<ColumnSymbol> BuildAsimColumns(
        string tableName,
        Dictionary<string, string> extra,
        Dictionary<string, List<ColumnSymbol>> tableColumnMap)
    {
        var cols = new List<ColumnSymbol>();

        if (tableColumnMap.TryGetValue(tableName, out var tableColumns))
        {
            cols.AddRange(tableColumns);
        }

        var existing = new HashSet<string>(cols.Select(c => c.Name), StringComparer.OrdinalIgnoreCase);
        foreach (var (colName, colType) in extra)
        {
            if (existing.Add(colName))
            {
                var typeSymbol = ScalarTypes.GetSymbol(colType) ?? ScalarTypes.String;
                cols.Add(new ColumnSymbol(colName, typeSymbol));
            }
        }

        return cols;
    }
}
