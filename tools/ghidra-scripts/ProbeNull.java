// ProbeNull.java — probe for a null-terminated UTF-16 string (exact class-name shape).
//@category MT5
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class ProbeNull extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("usage: ProbeNull.java <ascii-string>"); return; }
        String p = args[0];
        // build UTF-16LE bytes + terminating NUL wchar
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        for (char c : p.toCharArray()) { bos.write(c & 0xFF); bos.write(0); }
        bos.write(0); bos.write(0);
        byte[] needle = bos.toByteArray();
        Memory mem = currentProgram.getMemory();
        int hits = 0;
        Address start = mem.getMinAddress();
        while (hits < 20) {
            if (monitor.isCancelled()) return;
            Address hit = mem.findBytes(start, needle, null, true, monitor);
            if (hit == null) break;
            MemoryBlock blk = mem.getBlock(hit);
            println(String.format("EXACT \"%s\\0\" @ %s block=%s", p, hit, blk != null ? blk.getName() : "?"));
            hits++;
            start = hit.add(needle.length);
        }
        if (hits == 0) println("EXACT \"" + p + "\": 0 hits");
    }
}
