// ProbeOne.java — probe the binary for a single string (ASCII + UTF16).
//@category MT5
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.charset.StandardCharsets;

public class ProbeOne extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("usage: ProbeOne.java <string>"); return; }
        String p = args[0];
        Memory mem = currentProgram.getMemory();
        byte[][] encs = { p.getBytes(StandardCharsets.US_ASCII), p.getBytes(StandardCharsets.UTF_16LE) };
        String[] kinds = { "ASCII", "UTF16" };
        for (int i = 0; i < encs.length; i++) {
            int hits = 0;
            Address start = mem.getMinAddress();
            while (hits < 15) {
                if (monitor.isCancelled()) return;
                Address hit = mem.findBytes(start, encs[i], null, true, monitor);
                if (hit == null) break;
                MemoryBlock blk = mem.getBlock(hit);
                println(String.format("PROBE[%s] \"%s\" @ %s block=%s", kinds[i], p, hit, blk != null ? blk.getName() : "?"));
                hits++;
                start = hit.add(encs[i].length);
            }
            if (hits == 0) println("PROBE[" + kinds[i] + "] \"" + p + "\": 0 hits");
        }
    }
}
