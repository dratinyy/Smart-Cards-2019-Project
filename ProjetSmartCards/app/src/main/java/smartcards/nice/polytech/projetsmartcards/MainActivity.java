package smartcards.nice.polytech.projetsmartcards;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final ListView recordListView = findViewById(R.id.recordList);

        final List<Record> records = new ArrayList<>();
        records.add(new Record(RecordType.TEXT_FR, "Salut"));
        records.add(new Record(RecordType.TEXT_EN, "Hey"));

        final RecordAdapter adapter = new RecordAdapter(this, records);
        recordListView.setAdapter(adapter);

        recordListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            @Override
            public void onItemClick(AdapterView<?> parent, final View view, final int position, long id) {
//                view.animate().setDuration(2000).alpha(0)
//                        .withEndAction(new Runnable() {
//                            @Override
//                            public void run() {
//                                records.remove(records.get(position));
//                                adapter.notifyDataSetChanged();
//                                view.setAlpha(1);
//                            }
//                        });
            }
        });
    }
}
