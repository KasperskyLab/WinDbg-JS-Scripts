## JS scripts for WinDbg

This is a collection of WinDbg JS scripts useful for dumps analysis.

### Basic usage:

To use JS scripts in WinDbg you need WinDbg Preview or regular WinDbg from February 2019 or later.

You can load scripts by hand:
1. Load JS engine first: .load jsprovider.dll
2. Then load script: .scriptload <файл скрипта с полным путём>

--or--

You can use it through the WinDbg extension gallery. This feature is available in WinDbg Preview 1.0.1902 and up or latest regular WinDbg.
Docs are here https://github.com/microsoft/WinDbg-Samples/tree/master/Manifest
Gallery describes all commands in all scripts and automatically loads the required script if you try to use a command from it.

The gallery has already been prepared here but one step needs to be done by hand.
1. The gallery files are: ManifestVersion.txt, manifest.N.xml and config.xml.template.
2. You have to copy config.xml.template to config.xml
3. Open config.xml in your favorite editor and for the LocalCacheRootFolder node set Value to the absolute path to that directory.
4. Save changes.
5. Open WinDbg with any dump - all you need is the WinDbg console.
6. Load the gallery with command: .settings load <config.xml with absoltute path>
7. If the command is absent then your WinDng is too old.
8. If config.xml was loaded successfully, save it: .settings save
9. Next close WinDbg, open again and try any script command - it should work without any additional action.

### Commands:

**common.js**

- **!exccandidates [0x<thread ID>]**
  Searches for possible exception records in stack
  of the thread specified by <thread ID> or in stack of the current thread.

- **!walk_stdmap 0x<head ptr>**
  Dumps all elements of the map (no interpretation, just dds) with address <head ptr>.
  The <head ptr> should be taken from _Myhead field of std::map

**noexcept.js**

- **!fix_stack**
  Try to show corrected stack of the current thread if it is shown wrong due to an exception from noexcept function.

**x64.js**

- **!x32stacks**
  Try to show x32 stacks of all threads in x64 kernel dump.
