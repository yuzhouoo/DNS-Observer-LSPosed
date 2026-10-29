package android.content;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.IOException;
/** Minimal JVM fixture for exercising extracted-script updates; not packaged in the app. */
public final class Context {
    private final File files,assets;
    public Context(File files,File assets){this.files=files;this.assets=assets;}
    public File getFilesDir(){return files;}
    public Assets getAssets(){return new Assets();}
    public final class Assets {
        public InputStream open(String name)throws IOException{return new FileInputStream(new File(assets,name));}
    }
}
