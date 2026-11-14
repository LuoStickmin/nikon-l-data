// Dump FR60 instructions in a range: args = start len
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class DumpRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long start = Long.decode(a[0]);
        long len = Long.decode(a[1]);
        long end = start + len;
        Address addr = toAddr(start);
        while (addr.getOffset() < end) {
            Instruction ins = getInstructionAt(addr);
            if (ins == null) {
                try { disassemble(addr); } catch (Exception e) { }
                ins = getInstructionAt(addr);
            }
            if (ins == null) {
                println(String.format("%06X  ??", addr.getOffset()));
                addr = addr.add(2);
            } else {
                println(String.format("%06X  %s", ins.getAddress().getOffset(), ins.toString()));
                addr = addr.add(ins.getLength());
            }
        }
    }
}
