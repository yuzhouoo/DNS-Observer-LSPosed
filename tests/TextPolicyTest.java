import dev.yz.dnsobserver.TextPolicy;
public class TextPolicyTest {
    static void check(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }
    public static void main(String[] args) {
        check(TextPolicy.clamp("ex\nam\rple.org", 100).equals("example.org"), "newlines");
        check(TextPolicy.clamp("abcdefgh", 3).equals("abc"), "length");
        check(TextPolicy.clamp(null, 3).equals(""), "null");
        check(TextPolicy.csv("hello\"world").equals("\"hello\"\"world\""), "CSV quotes");
        check(TextPolicy.csv("=SUM(1,1)").startsWith("\"'="), "formula injection");
        check(TextPolicy.csv("a\nb").equals("\"a b\""), "newline CSV");
        System.out.println("TextPolicy regression tests passed");
    }
}
