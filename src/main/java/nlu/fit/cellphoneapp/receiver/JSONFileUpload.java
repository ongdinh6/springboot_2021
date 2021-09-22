package nlu.fit.cellphoneapp.receiver;

import java.io.Serializable;

public class JSONFileUpload implements Serializable {
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public JSONFileUpload(String path) {
        this.path = path;
    }
}
