package esapi.fuzzing;

public class ValidationTuple {
private String context;
private String raw;
private String expected;

public String getContext() {
	return context;
}
public void setContext(String context) {
	this.context = context;
}
public String getRaw() {
	return raw;
}
public void setRaw(String raw) {
	this.raw = raw;
}
public String getExpected() {
	return expected;
}
public void setExpected(String expected) {
	this.expected = expected;
}

}
