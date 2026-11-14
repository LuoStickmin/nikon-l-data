import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        long val = Long.decode(getScriptArgs()[0]);
        Address a = toAddr(val);
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a);
        int n = 0;
        while (it.hasNext()) {
            Reference r = it.next();
            println(String.format("%s -> %s (%s)", r.getFromAddress(), a, r.getReferenceType()));
            n++;
        }
        println("total " + n);
    }
}
