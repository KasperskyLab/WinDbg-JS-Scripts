/*///////////////////////////////////////////////////////////////////////
MIT License

Copyright (c) 2021-2022 AO Kaspersky Lab. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
/*////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////
// Memory utilities
//
// Note! Parameters should be passed with 0x or in "". Otherwise you got an error "Error: Unable to bind name ...".
//
// !av_heap_alloc_stats <heap address>, <block size in hex> - walk list of memory blocks of specified size in heap and collect stats about allocation stacks.
//
// !heap_alloc_stats <heap_address> - walk list of memory blocks in the heap and collect stats about the contents
//
/////////////////////////////////////////////////////////////////////////

"use strict";

// Utilities
function GetStringParameter(param)
{
    if (typeof param == "object")
    {
        return param.toString(16);
    }

    return "" + param.toString(16);
}

function PrintCommandOutput(output)
{
    for (var line of output)
        host.diagnostics.debugLog(line + "\n");
}

function* CreateCacheReader(filename)
{
    var reader = host.namespace.Debugger.Utility.FileSystem.CreateTextReader(filename, "Utf8");
    try
    {
        for (var line = reader.ReadLine(); line.length > 0; line = reader.ReadLine())
        {
            yield line;
        }
    }
    catch(err)
    {
        if (err.message != "Cannot read past end of file") {
            host.diagnostics.debugLog("Cache read error: " + err.message + "\n");
        }
        return "";
    }

    return "";
}

function GetDataForProcessing(heap)
{
    var heapAddress = GetStringParameter(heap);
    var heapCacheFilename = "heap_" + heapAddress + ".cache";

    // cache filename have to depends on dump filename
    try {
        if (host.namespace.Debugger.Sessions[0].Attributes.Target.Details.DumpFileName.length > 0) {
            heapCacheFilename = host.namespace.Debugger.Sessions[0].Attributes.Target.Details.DumpFileName + "_" + heapCacheFilename;
        }
    } catch (err) {
        host.diagnostics.debugLog("Dump name getting error: " + err.message + "\n");
    }

    if (host.namespace.Debugger.Utility.FileSystem.FileExists(heapCacheFilename)) {
        return CreateCacheReader(heapCacheFilename);
    }

    var output = host.namespace.Debugger.Utility.Control.ExecuteCommand("!heap -s -a -c -h " + heapAddress);
    var cacheFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(heapCacheFilename, "CreateAlways");
    var writer = host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(cacheFile, "Utf8");

    var errorCount = 0;
    var writeLineCount = 0;
    for (let line of output) {
        ++writeLineCount;
        try {
            if (line.length > 0) {
                writer.WriteLine(line);
            }
        } catch (err) {
            if (errorCount < 20) {
                host.diagnostics.debugLog("Cache write error at line " + writeLineCount.toString(10) + ": " + err.toString() + "\n");
            }
            ++errorCount;
        }
    }
    cacheFile.Close();
    host.diagnostics.debugLog("Total write errors: " + errorCount.toString(10) + "\n");
    return output;
}

function AddItem(stat, key)
{
    if (stat.has(key)) {
        stat.set(key, stat.get(key) + 1);
    } else {
        stat.set(key, 1);
    }
}

function __CollectAvHeapAllocationStats(heap, blockSize)
{
    var stat = new Map();
    var lineCount = 0;
    var output = GetDataForProcessing(heap);

    var regExpText = "^([0-9A-Fa-f]{8})\\sB\\sabcdaaa[0-9A-Fa-f]\\s[0-9A-Fa-f]{8}\\s" + ('0000000' + blockSize.toString(16)).slice(-8) + "\\s(.+)$";
    //host.diagnostics.debugLog("RegExp: " + regExpText + "\n");
    var lineRE = new RegExp(regExpText);

    var matched = 0;
    try
    {
        for (var line of output)
        {
            //host.diagnostics.debugLog("block " + line + "\n");
            ++lineCount;

            var parsed = line.match(lineRE);
            if (parsed) {
                ++matched;

                var address = host.parseInt64(parsed[1], 16);
                var stackPtr = host.parseInt64(host.memory.readMemoryValues(address + 0x20, 1, 4), 10);
                //host.diagnostics.debugLog("  " + address.toString(16) + " - " + stackPtr.toString(16) + "\n");
                AddItem(stat, stackPtr);
            }

        }
    }
    catch(err)
    {
        //host.diagnostics.debugLog("Error: " + err.toString() + "\n");
    }

    host.diagnostics.debugLog("Matched: 0x" + matched.toString(16) + " blocks\n");
    host.diagnostics.debugLog("-------------------------------------------------------------\n");

    // iterate map sorted by value
    stat[Symbol.iterator] = function* () {
        yield* [...this.entries()].sort((a, b) => b[1] - a[1]);
    }

    for (let [key, value] of stat) {
        host.diagnostics.debugLog("\n=== stack at 0x" + ('0000000' + key.toString(16)).slice(-8) + ' - ' + value.toString(10) + " blocks ===\n");

        var output = host.namespace.Debugger.Utility.Control.ExecuteCommand("dds " + (key + 0xC).toString(16) + " L20");
        PrintCommandOutput(output);
    }

    host.diagnostics.debugLog("\n");
    return lineCount;
}

function hex2ascii(str)
{
    var hex = str.toString();
    var res = '';
    for (var i = hex.length - 2; i >= 0; i -= 2) {
        var code = parseInt(hex.substr(i, 2), 16);
        if (code < 21) {
            res += ".";
        } else {
            res += String.fromCharCode(code);
        }
    }
    return res;
}

function PrintTopStats(stat)
{
    // iterate map sorted by value
    stat[Symbol.iterator] = function* () {
        yield* [...this.entries()].sort((a, b) => b[1] - a[1]);
    }

    var i = 0;
    for (let [key, value] of stat) {
        host.diagnostics.debugLog(key + " \"" + hex2ascii(key) + "\": " + value.toString(10) + "\n");
        if (++i > 10) {
            break;
        }
    }
}

function __CollectHeapAllocationStats(heap) {
    var stat_Dword1 = new Map();
    var stat_Dword2 = new Map();
    var stat_Dword3 = new Map();
    var stat_Dword4 = new Map();
    var stat_Qword1 = new Map();
    var stat_Qword2 = new Map();
    var lineCount = 0;
    var output = GetDataForProcessing(heap);

    var regExpText = "^[0-9A-Fa-f]{8,16}\\s[bB]\\s([0-9A-Fa-f]{8})\\s([0-9A-Fa-f]{8})\\s([0-9A-Fa-f]{8})\\s([0-9A-Fa-f]{8})\\s(.+)$";
    //host.diagnostics.debugLog("RegExp: " + regExpText + "\n");
    var lineRE = new RegExp(regExpText);

    var matched = 0;
    try {
        for (var line of output) {
            //host.diagnostics.debugLog("block " + line + "\n");
            ++lineCount;

            var parsed = line.match(lineRE);
            if (parsed) {
                ++matched;
                //host.diagnostics.debugLog("Parsed\n  " + parsed[1] + "\n  " + parsed[2] + "\n  " + parsed[3] + "\n  " + parsed[4] + "\n");

                AddItem(stat_Dword1, parsed[1]);
                AddItem(stat_Dword2, parsed[2]);
                AddItem(stat_Dword3, parsed[3]);
                AddItem(stat_Dword4, parsed[4]);
                AddItem(stat_Qword1, parsed[2] + parsed[1]);
                AddItem(stat_Qword2, parsed[4] + parsed[3]);
            }
        }
    }
    catch (err) {
        //host.diagnostics.debugLog("Error: " + err.toString() + "\n");
    }

    host.diagnostics.debugLog("Matched: 0x" + matched.toString(16) + " blocks\n");
    
    host.diagnostics.debugLog("\n--- Top by first dword ---\n");
    PrintTopStats(stat_Dword1);
    host.diagnostics.debugLog("\n--- Top by second dword ---\n");
    PrintTopStats(stat_Dword2);
    host.diagnostics.debugLog("\n--- Top by third dword ---\n");
    PrintTopStats(stat_Dword3);
    host.diagnostics.debugLog("\n--- Top by fourth dword ---\n");
    PrintTopStats(stat_Dword4);
    host.diagnostics.debugLog("\n--- Top by first qword ---\n");
    PrintTopStats(stat_Qword1);
    host.diagnostics.debugLog("\n--- Top by second qword ---\n");
    PrintTopStats(stat_Qword2);

    host.diagnostics.debugLog("\n");
    return lineCount;
}

// Register aliases
function initializeScript()
{
    return [new host.apiVersionSupport(1, 2),
        new host.functionAlias(__CollectAvHeapAllocationStats, "av_heap_alloc_stats"),
        new host.functionAlias(__CollectHeapAllocationStats, "heap_alloc_stats")];
}
