import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("Starting decompilation...");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        String filter = ""; // Function filter from GUI
        
        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function function : functionManager.getFunctions(true)) {
            try {
                String funcName = function.getName();
                
                // Apply filter if it exists
                if (!"".equals(filter) && !funcName.contains(filter)) {
                    continue;
                }
                
                println("\n==== DECOMPILING: " + funcName + " ====");
                println("Address: " + function.getEntryPoint());
                
                // Get decompiled code
                DecompileResults results = decompiler.decompileFunction(function, 30, null);
                
                if (results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                } else {
                    println("Failed to decompile. Errors:");
                    for (String error : results.getErrorMessages()) {
                        println("  " + error);
                    }
                }
            } catch (Exception e) {
                println("Error decompiling " + function.getName() + ": " + e.getMessage());
            }
        }
        
        println("\nDecompilation complete.");
    }
}
