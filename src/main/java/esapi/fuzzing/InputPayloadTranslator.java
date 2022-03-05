package esapi.fuzzing;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.JavaScriptCodec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class InputPayloadTranslator{
	private static final String I_KNOW_BETTER = "Enter My Own";
	
	public void eval(File source, File outFile) throws FileNotFoundException, IOException, InterruptedException {
		HTMLEntityCodec esapiHtml = new HTMLEntityCodec();
		JavaScriptCodec esapiJs = new JavaScriptCodec();

		List<ValidationTuple> reviewed = new ArrayList<>();
		
		try (BufferedReader reader = new BufferedReader(new FileReader(source) ) ){
			String line = reader.readLine();
			while (line != null) {
				System.out.println("The Line is:");
				System.out.println("\t" + line);
				
				System.out.println("Identify the syntax:");

				String type = chooseOption("HTML", "Javascript");
				
				System.out.println("Choose the best match:");
				String choice = null;
				switch (type.toLowerCase()) {
				case "html":
					String esapiVal=esapiHtml.encode(new char[] { ',', '.', '-', '_' }, line);
					String owaspEncode = Encode.forHtml(line);
					String apache4Val = StringEscapeUtils.ESCAPE_HTML4.translate(line);
					String apache3Val = StringEscapeUtils.ESCAPE_HTML3.translate(line);
					
					choice = chooseOption(esapiVal, owaspEncode, apache4Val, apache3Val, I_KNOW_BETTER);
					break;
				case "javascript":
					String esapiJsVal= esapiJs.encode(new char[] {',', '.', '_' }, line); 
					String owaspEncodeJs = Encode.forJavaScript(line);
					String apacheECMA = StringEscapeUtils.escapeEcmaScript(line);
					choice = chooseOption(esapiJsVal, owaspEncodeJs, apacheECMA, I_KNOW_BETTER);
					
					break;

				default:
					break;
				}
				
				
				
				if (I_KNOW_BETTER.equals(choice)) {
					//Don't close System.in
					@SuppressWarnings("resource")
					Scanner sc= new Scanner(System.in);
					System.out.print("Enter the expected Translation: ");
					choice = sc.nextLine();
				}
				
				ValidationTuple tpl = new ValidationTuple();
				tpl.setContext(type.toLowerCase());
				tpl.setRaw(line);
				tpl.setExpected(choice);
				
				reviewed.add(tpl);
						
				line = reader.readLine();
			}		
		}
		GsonBuilder bldr = new GsonBuilder();
		bldr.setPrettyPrinting();
		Gson gson = bldr.create();
		
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(outFile) ) ){
			writer.write(gson.toJson(reviewed));
		}
		
	}
	
	private String chooseOption( String...options) {
		List<String> opts = Arrays.asList(options);
		//Don't close System.in
		@SuppressWarnings("resource")
		Scanner sc= new Scanner(System.in);
		for (int index = 0; index < opts.size(); index ++) {
			System.out.println(String.format("    %s: %s", index, opts.get(index)));
		}
		
		int choice = -1;
		
		while (choice < 0 || choice >= opts.size()) {
			System.out.println("Enter the number of your choice:");
			choice = sc.nextInt();
		}
		
		return opts.get(choice);
	}
	
	public static void main(String[] args) throws FileNotFoundException, IOException, InterruptedException {
		String attacksBasePath = args[0];
		File outputFile = new File(args[1]);
		
		if (!outputFile.exists() && outputFile.createNewFile()) {
			throw new IOException("Failed to create output file: " + outputFile);
		}
		
		
		File attackResources = new File(attacksBasePath);


		String[] paths = attackResources.list(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return new File(dir, name).isDirectory();
			}
		});

		for (String path : paths) {
			File file = new File(attacksBasePath+path);
			File[] files = file.listFiles(new FilenameFilter() {
				public boolean accept(File dir, String name) {
					return new File(dir, name).isFile();
				}
			});

			InputPayloadTranslator eval = new InputPayloadTranslator();
			
			for (File fn : files) {
				String fileName = fn.getCanonicalPath().substring(fn.getCanonicalPath().lastIndexOf(File.separator)+1);
				System.out.println("Processing: " + fileName);
				eval.eval(fn, outputFile);
			}
		}
	}
}
