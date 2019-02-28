package smartcards.nice.polytech.projetsmartcards;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.List;

public class RecordAdapter extends ArrayAdapter {
    private final Context context;
    private final List<Record> values;

    public RecordAdapter(Context context, List<Record> values) {
        super(context, -1, values);
        this.context = context;
        this.values = values;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        LayoutInflater inflater = (LayoutInflater) context
                .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View rowView = inflater.inflate(R.layout.record, parent, false);
        TextView recordTypeView = rowView.findViewById(R.id.recordType);
        TextView recordDataView = rowView.findViewById(R.id.recordData);
        recordTypeView.setText(this.values.get(position).getType().toString());
        recordDataView.setText(this.values.get(position).getData());

        return rowView;
    }
}
