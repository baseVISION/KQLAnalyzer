Fix problem with double quoted literals at the end
Double-quoted literals are causing problems when they are at the end before another line is injected via extend.
0405f7c
KQLAnalyzer.Tests\AnalyzeQueryTests.cs
            Assert.Contains(results.ParsingErrors,(e => e.Code == "KS119")); // Expect KS119 error The function 'MyFunction' expects 1 argument.
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
    }
}
