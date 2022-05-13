#/usr/bin/python
#
##################################################################################
#
# MIT License
#
# Copyright (c) 2022 AO Kaspersky Lab. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
##################################################################################
#
# Memory utilities
#

import chunk
import struct
import sys
from functools import lru_cache
import gdb

def CastULong(v):
    mask = (1 << 64) - 1
    return int(v.cast(gdb.Value(mask).type)) & mask

def AlignAddress(address, align):
    return address + ((align - (address % align)) % align)

@lru_cache()
def ReadMemory_Int(addr):
    """Return an integer read from memory."""
    sz = 8
    mem = gdb.selected_inferior().read_memory(addr, sz).tobytes()
    return struct.unpack("{}Q".format('<'), mem)[0]

@lru_cache()
def LookupType(name):
    try:
        return gdb.lookup_type(name).strip_typedefs()
    except RuntimeError:
        return None

def FindHeapBase():
    return int(gdb.parse_and_eval("mp_->sbrk_base"))

def FindMainArena():
    return AlignAddress(CastULong(gdb.parse_and_eval("(void *)&__malloc_hook")) + 8, 0x20)

class Arena:
    """Heap arena class"""

    def __init__(self, addr, malloc_state_type):
        arena = gdb.parse_and_eval("*{:#x}".format(addr))
        self.m_addr = int(arena.address)
        self.m_arena = arena.cast(malloc_state_type)
        return

    def __getitem__(self, item):
        return self.m_arena[item]

    def __getattr__(self, attr):
        return self.m_arena[attr]

def GetMainArena():
    malloc_state_type = LookupType("struct malloc_state")
    main_arena = FindMainArena()
    return Arena(main_arena, malloc_state_type)


class Chunk:
    """Heap chunk class"""

    def __init__(self, addr):
        self.ptrsize = 8
        self.base_address = addr
        self.address = addr + 2 * self.ptrsize
        self.size_addr = int(self.address - self.ptrsize)
        self.prev_size_addr = self.base_address
        return

    @property
    def size(self):
        return ReadMemory_Int(self.size_addr) & (~0x07)

    @property
    def user_size(self):
        current_size = self.size
        if current_size == 0:
            return current_size
        if self.m_bit:
            return current_size - 2 * self.ptrsize
        return current_size - self.ptrsize

    @property
    def prev_chunk_size(self):
        return ReadMemory_Int(self.prev_size_addr)

    def get_next_chunk(self):
        return Chunk(self.base_address + self.size)

    @property
    def p_bit(self):
        return ReadMemory_Int(self.size_addr) & 0x01 == 0x01

    @property
    def m_bit(self):
        return ReadMemory_Int(self.size_addr) & 0x02 == 0x02

    @property
    def a_bit(self):
        return ReadMemory_Int(self.size_addr) & 0x04 == 0x04

    @property
    def busy(self):
        if self.m_bit:
            return True
        return self.get_next_chunk().p_bit

def GetChunks():
    addr = FindHeapBase()
    main_arena = GetMainArena()
    while True:
        chunk = Chunk(addr)
        yield chunk
        if chunk.size == 0:
            break
        addr += chunk.size
        if addr >= main_arena.top:
            break


def AddItem(d, val):
    if d.get(val) is None:
        d[val] = 1
    else:
        d[val] = d[val] + 1

def SplitStringIntoTwixes(s):
    for pos in range(len(s), 1, -2):
        i = int(s[pos-2:pos], 16)
        yield chr(i) if i > 21 else '.'

def HexIntToAscii(v):
    return "".join(SplitStringIntoTwixes(v))

def PrintTopStats(d):
    s = sorted(d.items(), key=lambda x: x[1], reverse=True)
    i = 0
    for k, v in s:
        print("{} - '{}': {}".format(k, HexIntToAscii(k), v))
        i = i + 1
        if i > 10:
            break

class HeapAllocStats(gdb.Command):
    """Collect heap allocation stats"""

    def __init__ (self):
        super (HeapAllocStats, self).__init__ ("heap_alloc_stats", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        if gdb.selected_inferior().pid == 0:
            print("There is no running program\n")
            return

        stat_int1 = dict();
        stat_int2 = dict();
        stat_int3 = dict();
        stat_int4 = dict();
        stat_double_int1 = dict();
        stat_double_int2 = dict();
        stat_quad_int = {};
        busy_chunk_count = 0

        for ch in GetChunks():
            if ch.busy:
                busy_chunk_count = busy_chunk_count + 1
                size = ch.user_size
                i1 = 0
                i2 = 0
                i3 = 0
                i4 = 0
                if size >= 32:
                    i1 = ReadMemory_Int(ch.address)
                    i2 = ReadMemory_Int(ch.address + 8)
                    i3 = ReadMemory_Int(ch.address + 16)
                    i4 = ReadMemory_Int(ch.address + 24)
                elif size >= 24:
                    i1 = ReadMemory_Int(ch.address)
                    i2 = ReadMemory_Int(ch.address + 8)
                    i3 = ReadMemory_Int(ch.address + 16)
                elif size >= 16:
                    i1 = ReadMemory_Int(ch.address)
                    i2 = ReadMemory_Int(ch.address + 8)
                elif size >= 8:
                    i1 = ReadMemory_Int(ch.address)
                else:
                    continue
                AddItem(stat_int1, "{:016x}".format(i1))
                AddItem(stat_int2, "{:016x}".format(i2))
                AddItem(stat_int3, "{:016x}".format(i3))
                AddItem(stat_int4, "{:016x}".format(i4))
                AddItem(stat_double_int1, "{:016x}{:016x}".format(i2, i1))
                AddItem(stat_double_int2, "{:016x}{:016x}".format(i4, i3))
                AddItem(stat_quad_int, "{:016x}{:016x}{:016x}{:016x}".format(i4, i3, i2, i1))
        print("Total {} busy chunks\n".format(busy_chunk_count))

        print("--- Top by first int ---");
        PrintTopStats(stat_int1);
        print("\n--- Top by second int ---\n");
        PrintTopStats(stat_int2);
        print("\n--- Top by third int ---\n");
        PrintTopStats(stat_int3);
        print("\n--- Top by fourth int ---\n");
        PrintTopStats(stat_int4);
        print("\n--- Top by first double int ---\n");
        PrintTopStats(stat_double_int1);
        print("\n--- Top by second double int ---\n");
        PrintTopStats(stat_double_int2);
        print("\n--- Top by quad int ---\n");
        PrintTopStats(stat_quad_int);


if __name__ == "__main__":

    if sys.version_info[0] == 2:
        err("Python3 is required")

    else:
        gdb.execute("set python print-stack full")

        HeapAllocStats()
