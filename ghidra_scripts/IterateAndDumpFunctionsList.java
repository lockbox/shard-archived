// Iterates over all functions in the current program and dumps contents to disk
// to be consumed by `struct.foo`
//@category Iteration
//@author lockbox

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class IterateAndDumpFunctionsList extends GhidraScript {

	public static final String NAME = "name";
	public static final String BASE_ADDRESS = "base_address";
	public static final String DATA = "data";

	@Override
	public void run() throws Exception {
		try {
			File file = askFile("Output File", "Select output file to dump function metadata");
			dumpFunctions(file);
		} catch (CancelledException e) {
			println("Cancelling script...");
		}

	}

	// copied from https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
	public static String bytesToHex(byte[] bytes) {
	    byte[] hexChars = new byte[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars, StandardCharsets.UTF_8);
	}
	// end copy

	private void dumpFunctions(File out) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		try {
			// initialize the writer
			JsonWriter jsonWriter = new JsonWriter(new FileWriter(out));
			jsonWriter.beginArray();

			Listing listing = currentProgram.getListing();
			FunctionIterator iter = listing.getFunctions(true);
			while (iter.hasNext() && !monitor.isCancelled()) {
				Function f = iter.next();

				// build the properties for each object we're going to write
				// for the emitted functions
				String name = f.getName();
				long entry = f.getEntryPoint().getUnsignedOffset();
				// +1 because the "max unsigned offset" is the address of the last byte
				long max_address = f.getBody().getMaxAddress().getUnsignedOffset() + 1;
				long size = max_address - f.getBody().getMinAddress().getUnsignedOffset();
				Memory memory = currentProgram.getMemory();
				byte[] function_bytes = new byte[(int) size];

				// get the actual function bytes
				int count = memory.getBytes(f.getEntryPoint(), function_bytes);
				if (count != size) {
					println("!!! Warning: only read " + count + " bytes from memory instead of the requested" + size);
				}

				JsonObject json = new JsonObject();
				json.addProperty(NAME, name);
				json.addProperty(BASE_ADDRESS, entry);
				json.addProperty(DATA, bytesToHex(function_bytes));

				gson.toJson(json, jsonWriter);
			}

			jsonWriter.endArray();
			jsonWriter.close();

		} catch (IOException e) {
			println("!!! failed to write to file provided: " + out);
		} catch (MemoryAccessException e) {
			println("!!! Accessed invalid memory while attempting to dump data");
		}
	}

}
