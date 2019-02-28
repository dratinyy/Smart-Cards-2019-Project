package smartcards.nice.polytech.projetsmartcards;

public class Record {
    private RecordType type;
    private String data;

    public Record(RecordType type, String data) {
        this.type = type;
        this.data = data;
    }
    public RecordType getType() {
        return type;
    }

    public void setType(RecordType type) {
        this.type = type;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
