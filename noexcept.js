/*///////////////////////////////////////////////////////////////////////
MIT License

Copyright (c) 2020-2022 AO Kaspersky Lab. All Rights Reserved.

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

"use strict";

/////////////////////////////////////////////////////////////////////////
//
// !fix_stack - try to show corrected stack of the current thread if it is shown wrong due to an exception from noexcept function
//
/////////////////////////////////////////////////////////////////////////

// Try to print fixed stack of the current thread
function __FixStack()
{
    var mode = 0;
    var lineRE = /^([0-9A-Fa-f]{1,4})\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(.+)$/;
    var prevEBP = "";
    var warningFound = false;
    var linesMap = new Map();
    var output = host.namespace.Debugger.Utility.Control.ExecuteCommand("kb");
    for (var line of output)
    {
        if (mode == 0)
        {// search for keyword
            if (!warningFound && line.includes("Following frames may be wrong."))
            {
                warningFound = true;
                continue;
            }
            else if (line.includes("ntdll!ExecuteHandler2+"))
            {
                if (warningFound)
                {
                    mode = 2
                }
                else
                {
                    mode = 1
                }
            }
            else
            {
                host.diagnostics.debugLog(line + "\n");

                var parsed = line.match(lineRE);
                if (parsed)
                {
                    prevEBP = parsed[2];
                }
            }
        }
        else if (mode == 1)
        {// search for warning
            if (line.includes("Following frames may be wrong."))
            {
                warningFound = true;
                mode = 2;
            }
        }
        else
        {// fill map
            var parsed = line.match(lineRE);
            if (parsed)
            {
                // skip addresses without symbols
                if (parsed[7].startsWith("0x"))
                {
                    continue;
                }

                // skip some symbols
                if (!["ntdll!ExecuteHandler2+", "ntdll!ExecuteHandler+", "ntdll!KiUserExceptionDispatcher+", "KERNELBASE!RaiseException+"]
                    .every(str => !parsed[7].startsWith(str)))
                {
                    continue;
                }

                linesMap.set(parsed[2], line);
            }
        }
    }

    if (!warningFound || (prevEBP.length == 0))
    {
        host.diagnostics.debugLog("Error: nothing to fix\n");
        return 1;
    }

    var nextCaller = "";
    var nextAddress = "";
    var ebpRE = /^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)/;
    var symRE = /^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s*(.*)$/;
    for (; prevEBP != "00000000";)
    {
        if (nextCaller.length > 0)
        {
            host.diagnostics.debugLog("-- " + prevEBP + " " + nextAddress + " 00000000 00000000 00000000 " + nextCaller + "\n");
        }

        var output = host.namespace.Debugger.Utility.Control.ExecuteCommand("dds " + prevEBP + " L2");
        if (output.length < 2)
        {
            host.diagnostics.debugLog("Error: nothing to parse\n");
            break;
        }

        var parsedEbp = output[0].match(ebpRE);
        if (!parsedEbp)
        {
            host.diagnostics.debugLog("Error: cannot find next frame\n");
            break;
        }

        var newEbp = parsedEbp[2];
        var zero = true;
        for (let letter of newEbp) {
            if (letter != '0')
            {
                zero = false;
                break;
            }
        }
        if (zero)
        {// end of stack
            break;
        }

        prevEBP = newEbp;

        // search map for it
        if (linesMap.has(prevEBP))
        {
            var print = false;
            var it = linesMap.entries();
            for (let item of it)
            {
                if (print)
                {
                    host.diagnostics.debugLog(item[1] + "\n");
                }
                else if (item[0] == prevEBP)
                {
                    print = true;
                    host.diagnostics.debugLog(item[1] + "\n");
                }
            }
            break;
        }

        // get symbol
        var parsedSym = output[1].match(symRE);
        if (!parsedSym)
        {
            host.diagnostics.debugLog("Error: cannot find next symbol\n");
            break;
        }

        nextAddress = parsedSym[2];
        nextCaller = parsedSym[3];
    }

    return 0;
}

// Register aliases
function initializeScript()
{
    return [new host.apiVersionSupport(1, 2),
            new host.functionAlias(__FixStack, "fix_stack")];
}
