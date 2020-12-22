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
// Common utilities
//
// Note! Parameters should be passed with 0x or in "". Otherwise you got an error "Error: Unable to bind name ...".
//
// !exccandidates [<thread id>] - search for exception candidates in the specified thread. If no thread is specified current one will be used.
//
// !walk_stdmap <head ptr(_Myhead field of std::map)> - walk std::map blocks
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

// Search thread stack for exception candidates (x86 only)
function GetStackBase(thread)
{
    var StackBase = 0;

    // try to get stack limits from the TEB
    try
    {
        if (thread == 0)
        {// current thread
            host.diagnostics.debugLog("Searching for exception candidate in current thread\n");
            StackBase = host.currentThread.Environment.EnvironmentBlock.NtTib.StackBase.address - 0x100000;
        }
        else
        {
            var threadId = GetStringParameter(thread);
            host.diagnostics.debugLog("Searching for exception candidate in thread with TID 0x" + threadId + "\n");
            StackBase = host.currentProcess.Threads[Number.parseInt(threadId, 16)].Environment.EnvironmentBlock.NtTib.StackBase.address - 0x100000;
        }
        return StackBase;
    }
    catch (err)
    {
        host.diagnostics.debugLog("Error " + err.name + ": " + err.message + "\n");
    }

    // Oops, TEB is unavalable, guess by ESP
    host.diagnostics.debugLog("Guess stack limits by ESP\n");
    if (thread == 0)
    {// current thread
        StackBase = host.currentThread.Registers.User.esp & 0xFFF00000;
    }
    else
    {
        var threadId = GetStringParameter(thread);
        StackBase = host.currentProcess.Threads[Number.parseInt(threadId, 16)].Registers.User.esp & 0xFFF00000;
    }
    return StackBase;
}

function __FindExceptionCandidates(thread = 0)
{
    var SearchBase = GetStackBase(thread);
    host.diagnostics.debugLog("Stack top: 0x" + SearchBase.toString(16) + "\n\n");

    // search in stack sequence of values @gs @fs @es @ds
    var ctl = host.namespace.Debugger.Utility.Control;
    var cmd = "s -[1]d 0x" + SearchBase.toString(16) + " L?0x100000 @gs @fs @es @ds";
    var output = ctl.ExecuteCommand(cmd);
    var foundCount = 0;
    for (var line of output)
    {
        if (line.length == 0)
            continue;

        // found entries
        var address = host.parseInt64(line, 16);
        address = address - 0x8c;
        
        // try to find exception record
        var output1 = ctl.ExecuteCommand("s -[1]d " + (address - 0x100).toString(16) + " L0x100 0x" + address.toString(16));
        var nearestEntry = 0;
        try
        {
            for (var line1 of output1)
            {
                nearestEntry = host.parseInt64(line1, 16);
            }
        }
        catch(err)
        {
            nearestEntry = 0;
        }
        
        // ok, found
        if (nearestEntry != 0)
        {
            var erAddress = host.memory.readMemoryValues(nearestEntry - 4, 1, 4, false);
            var exceptionCode = host.memory.readMemoryValues(nearestEntry + 4, 1, 4, false);
            host.diagnostics.debugLog("Found exception " + foundCount++ + "\n");
            host.diagnostics.debugLog(".exr 0x" + erAddress[0].toString(16) + " - exception code 0x" + exceptionCode[0].toString(16) + "\n");
            host.diagnostics.debugLog(".cxr 0x" + address.toString(16) + "\n");
        }
    }
    
    if (foundCount == 0)
        host.diagnostics.debugLog("No exception candidate found\n");
    
    return foundCount;
}

// Walk std::map blocks (x86 only)
function __DumpStdMapItem(item, head, count)
{
    host.diagnostics.debugLog("\nItem 0x" + item.toString(16) + "\n----------------------------------------------------\n");
    PrintCommandOutput(host.namespace.Debugger.Utility.Control.ExecuteCommand("ddp 0x" + (item + 12).toString(16)));
    ++count.val;
    
    var left = host.memory.readMemoryValues(item + 0, 1, 4, false);
    if (left[0] != head)
        __DumpStdMapItem(left[0], head, count);
    var right = host.memory.readMemoryValues(item + 8, 1, 4, false);
    if (right[0] != head)
        __DumpStdMapItem(right[0], head, count);
}

function __WalkStdMap(head)
{
    var headPtrStr = GetStringParameter(head);
    var headPtr = Number.parseInt(headPtrStr, 16);
    host.diagnostics.debugLog("Walking std::map from head 0x" + headPtr.toString(16) + "\n");

    // get parent item - the real head of map
    var ctl = host.namespace.Debugger.Utility.Control;
    var realHead = host.memory.readMemoryValues(headPtr + 4, 1, 4, false);
    host.diagnostics.debugLog("Root entry 0x" + realHead[0].toString(16) + "\n");
    let count = {val: 0};
    if (realHead[0] != headPtr)
        __DumpStdMapItem(realHead[0], headPtr, count);

    host.diagnostics.debugLog("\nMap has " + count.val.toString() + " items\n");
    return count.val;
}

// Register aliases
function initializeScript()
{
    return [new host.apiVersionSupport(1, 2),
            new host.functionAlias(__FindExceptionCandidates, "exccandidates"),
            new host.functionAlias(__WalkStdMap, "walk_stdmap")];
}
