/*///////////////////////////////////////////////////////////////////////
MIT License

Copyright (c) 2020 AO Kaspersky Lab. All Rights Reserved.

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
// x64 utilities
//
// Note! Parameters should be passed with 0x or in "". Otherwise you got an error "Error: Unable to bind name ...".
//
// !x32stacks <process> - dump x32 stacks of specified process
//
/////////////////////////////////////////////////////////////////////////

"use strict";
 
 function GetStringParameter(param)
{
    if (typeof param == "object")
    {
        return param.toString(16);
    }

    return "" + param;
}

// Display x32 stacks of threads of process
function __X32Stacks(proc)
{
    var procId = GetStringParameter(proc);
    
    host.diagnostics.debugLog("Dumping x32 stacks of process " + procId + "\n\n");
    
    var reThread = /^\s*THREAD\s+([0-9,a-f]+)\s+Cid.*/;
    
    var ctl = host.namespace.Debugger.Utility.Control;   
    ctl.ExecuteCommand(".process /p /r " + procId);
    var output = ctl.ExecuteCommand("!process " + procId + " 4");
    var threadCount = 0;
    for (var line of output)
    {
        //host.diagnostics.debugLog(line + "\n");
        var res = line.match(reThread);
        if (res != null)
        {
            host.diagnostics.debugLog("Thread " + res[1] + "\n");
            var output1 = ctl.ExecuteCommand(".thread /w " + res[1] + "; k");
            for (var line1 of output1)
            {
                host.diagnostics.debugLog(line1 + "\n");
            }
            host.diagnostics.debugLog("\n");
            ++threadCount;

            var output2 = ctl.ExecuteCommand("!wow64exts.sw");
            for (var line2 of output2)
            {
                if (line2.indexOf("Switched to Guest (WoW) mode") != -1)
                {
                    ctl.ExecuteCommand("!wow64exts.sw");
                    break;
                }
            }
        }
    }
    
    return threadCount;
}

// Register aliases
function initializeScript()
{
    return [new host.apiVersionSupport(1, 2),
            new host.functionAlias(__X32Stacks, "x32stacks")];
}
