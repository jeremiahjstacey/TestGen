package esapi.fuzzing;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.esapi.reference.validation.HTMLValidationRule;

@RunWith(Parameterized.class)
public class AttackTest {


	@Parameters (name = "{0} (Line {1})")
	public static Object[] buildParams() throws Throwable {
		Collection<Object[]> testArgs = new ArrayList<Object[]>();

		String attacksBasePath = "src/test/resources/attacks/";

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

			for (File fn : files) {
				String fileName = fn.getCanonicalPath().substring(fn.getCanonicalPath().lastIndexOf(File.separator)+1);

				try (BufferedReader reader = new BufferedReader(new FileReader(fn) ) ){
					int linecounter = 1;
					String line = reader.readLine();
					while (line != null) {

						testArgs.add(new Object[] {String.format("%s/%s", path, fileName), linecounter++, line});
						line = reader.readLine();
					}
				}
			}
		}

		return testArgs.toArray();
	}


	private String input;
	public AttackTest (String source, int lineNum, String input) {
		this.input = input;
	}

	@Test
	public void checkInput() throws IntrusionException, ValidationException {
		boolean handled=true;
		String result;
		try {
			HTMLValidationRule hvr = new HTMLValidationRule( "safehtml", ESAPI.encoder() );
			hvr.setMaximumLength(Integer.MAX_VALUE);
			hvr.setAllowNull(false);
			result = hvr.getValid(AttackTest.class.getSimpleName(), input);
			assertNotEquals(input, result);
			handled = false;
		} catch (ValidationException | IntrusionException ex) {
			//
		}
		if (!handled) {
			fail("No Validation Exception and input was unmodified");
		}
		//ESAPI.validator().getValidSafeHTML("test", badVoodoo, 100, false, errors);
	}
}
