// FindOrderStrings.java — Ghidra headless script (NO auto-analysis needed).
// Scans every initialized memory block for UTF-16LE and ASCII "New Order"
// and prints each hit with its block name + neighbors' first bytes.
//@category MT5
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.charset.StandardCharsets;

public class FindOrderStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        byte[][] needles = {
            "New Order".getBytes(StandardCharsets.UTF_16LE),
            "New Order".getBytes(StandardCharsets.US_ASCII),
        };
        String[] labels = { "UTF16", "ASCII" };
        // .rsrc holds hundreds of menu copies; the interesting hits are in
        // code/data sections (.text/.rdata/.data/.cod*)
        java.util.Set<String> skip = new java.util.HashSet<>();
        skip.add(".rsrc");
        int total = 0;
        for (int n = 0; n < needles.length; n++) {
            byte[] needle = needles[n];
            for (MemoryBlock blk : mem.getBlocks()) {
                if (skip.contains(blk.getName()) || !blk.isInitialized()) continue;
                Address start = blk.getStart();
                while (true) {
                    if (monitor.isCancelled()) return;
                    Address hit = mem.findBytes(start, needle, null, true, monitor);
                    if (hit == null || hit.compareTo(blk.getEnd()) > 0) break;
                    println(String.format("HIT[%s] %s block=%s", labels[n], hit, blk.getName()));
                    total++;
                    start = hit.add(needle.length);
                    if (total > 300) { println("...cap reached"); println("TOTAL_HITS=" + total); return; }
                }
            }
        }
        println("TOTAL_HITS=" + total);
    }
}
