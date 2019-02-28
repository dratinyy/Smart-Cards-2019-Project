package smartcards.nice.polytech.projetsmartcards;

public class NDEFDecoder {

    public static Record decode() {

        Record record = new Record(RecordType.TEXT_FR, "");

        /*

        int offset = 0;
        int me;

        do
        {
            // Parsing of the header (1st byte)
            byte header = ndef[offset++];
            int mb = (0b10000000 & header) >> 7;
            me = (0b01000000 & header) >> 6;
            int cf = (0b00100000 & header) >> 5;
            int sr = (0b00010000 & header) >> 4;
            int il = (0b00001000 & header) >> 3;
            int tnf = 0b00000111 & header;

            Console.WriteLine("mb = " + mb);
            Console.WriteLine("me = " + me);
            Console.WriteLine("cf = " + cf);
            Console.WriteLine("sr = " + sr);
            Console.WriteLine("il = " + il);
            Console.WriteLine("tnf = " + tnf);

            byte type_len = ndef[offset++];
            Console.WriteLine("type length = " + type_len);

            // Parsing of the payload length, different according to sr
            int payload_len;
            if (sr == 1)
            {
                payload_len = ndef[offset++];
            }
            else
            {
                payload_len = (ndef[offset] << 3 * 8) + (ndef[offset + 1] << 2 * 8) + (ndef[offset + 2] << 8) + ndef[offset + 3];
                offset += 4;
            }
            Console.WriteLine("Payload length = " + payload_len);

            // Parsing of the id length
            int id_len = 0;
            if (il == 1)
            {
                id_len = ndef[offset++];
            } // else id_len = 0
            Console.WriteLine("Id length = " + id_len);

            // Parsing of the type, on type_len bytes
            byte[] type = new byte[type_len];
            for (int i = 0; i < type_len; i++)
            {
                type[i] = ndef[offset++];
            }

            if(type[0] == 0x54)
            {
                Console.WriteLine("Type is text");
            }
            else if(type[0] == 0x55)
            {
                Console.WriteLine("Type is URI");
            }
            else if(type[0] == 0x53 && type[1] == 0x70)
            {
                Console.WriteLine("Type is smart poster");
            }
            else
            {
                Console.WriteLine("Type is: " + System.Text.Encoding.ASCII.GetString(type) + " (not supported)");
            }

            // Parsing of the id, on id_len bytes
            int id = 0;
            for (int i = 0; i < id_len; i++)
            {
                id += ndef[offset++] << (id_len - i - 1);
            }
            Console.WriteLine("Id = " + id);

            // We store the payload
            byte[] payload = new byte[payload_len];
            Array.Copy(ndef, offset, payload, 0, payload_len);
            offset += payload_len;

            // Different processing of the payload depending on the type
            if (type[0] == 0x54)
            {
                Decode_Text(payload, payload_len);
            }
            else if (type[0] == 0x55)
            {
                Decode_URI(payload, payload_len);
            }
            else if (type[0] == 0x53 && type[1] == 0x70)
            {
                Decode_NDEF(payload);
            }
            else //Unsupported type, we print it as ASCII
            {
                Console.WriteLine("PAYLOAD = " + BitConverter.ToString(payload));
                Console.WriteLine("PAYLOAD = " + System.Text.Encoding.ASCII.GetString(payload));
            }
        } while (me != 1);

        */

        return record;
    }
}
