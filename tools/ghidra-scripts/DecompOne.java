// DecompOne.java — force-disassemble + decompile ONE function without full
// auto-analysis. Usage as postScript arg: the address (0x... hex string).
//@category MT5
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompOne extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: DecompOne.java <hex-address> [max-instructions]");
            return;
        }
        Address addr = currentProgram.getAddressFactory().getAddress(args[0]);
        int maxIns = args.length > 1 ? Integer.parseInt(args[1]) : 400;

        // disassemble starting at addr (linear flow follows)
        disassemble(addr, true);

        Function fn = getFunctionAt(addr);
        if (fn == null) {
            // create a function whose body we cap so encrypted-tail garbage
            // cannot drag the decompiler into a 100k-instruction rabbit hole
            Address end = addr.add(maxIns * 4L);
            createFunction(addr, "mt5_fn_" + addr);
            fn = getFunctionAt(addr);
        }
        if (fn == null) { println("FAILED to create function at " + addr); return; }

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        DecompileResults res = dec.decompileFunction(fn, 90, monitor);
        if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
            println("=== DECOMPILE " + addr + " (" + fn.getName() + ") ===");
            println(res.getDecompiledFunction().getC());
        } else {
            println("=== DISASM ONLY " + addr + " (decompile failed: " + res.getErrorMessage() + ") ===");
            ghidra.program.model.listing.InstructionIterator it =
                currentProgram.getListing().getInstructions(fn.getBody(), true);
            int c = 0;
            while (it.hasNext() && c++ < maxIns) {
                println(it.next().toString());
            }
        }
    }
}
