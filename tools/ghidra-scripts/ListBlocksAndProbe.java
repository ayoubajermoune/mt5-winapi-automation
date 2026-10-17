// ListBlocksAndProbe.java — print memory blocks, then probe for known strings.
//@category MT5
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.charset.StandardCharsets;

public class ListBlocksAndProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock blk : mem.getBlocks()) {
            println(String.format("BLOCK %-10s %s-%s size=0x%x init=%b",
                blk.getName(), blk.getStart(), blk.getEnd(), blk.getSize(), blk.isInitialized()));
        }
        String[] probes = { "MetaTrader", "Terminal", "ChartsFrame", "Order" };
        for (String p : probes) {
            for (byte[] enc : new byte[][]{ p.getBytes(StandardCharsets.UTF_16LE),
                                            p.getBytes(StandardCharsets.US_ASCII) }) {
                Address start = mem.getMinAddress();
                int hits = 0;
                while (hits < 20) {
                    if (monitor.isCancelled()) return;
                    Address hit = mem.findBytes(start, enc, null, true, monitor);
                    if (hit == null) break;
                    MemoryBlock blk = mem.getBlock(hit);
                    println(String.format("PROBE \"%s\" %s @ %s block=%s",
                        p, (enc.length > 0 && enc[1] == 0 ? "UTF16" : "ASCII"),
                        hit, blk != null ? blk.getName() : "?"));
                    hits++;
                    start = hit.add(enc.length);
                }
            }
        }
    }
}
