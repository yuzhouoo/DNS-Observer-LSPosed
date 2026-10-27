package dev.yz.dnsobserver;

public final class TextPolicy {
    private TextPolicy() { }
    public static String clamp(String text, int max) {
        if (text == null) return "";
        if (text.length() > max) text = text.substring(0, max);
        StringBuilder b = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            // Remove non-printable characters to protect log UI / CSV.
            if (c < 32 || c == 127) continue;
            b.append(c);
        }
        return b.toString();
    }
    public static String csv(String value) {
        if (value == null) value = "";
        value = value.replace("\r", " ").replace("\n", " ");
        // Protect Excel/Sheets from CSV formula injection.
        if (!value.isEmpty() && (value.charAt(0) == '=' || value.charAt(0) == '+'
                || value.charAt(0) == '-' || value.charAt(0) == '@'
                || value.charAt(0) == '\t')) value = "'" + value;
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }
}
