package smartcards.nice.polytech.projetsmartcards;

import android.content.Context;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

public class cCardService extends HostApduService {

    byte[] CLA_INCONNUE = new byte[]{(byte) 0x6E, (byte) 0x00};
    byte[] INS_INCONNUE = new byte[]{(byte) 0x6D, (byte) 0x00};
    byte[] LC_INCORRECT = new byte[]{(byte) 0x67, (byte) 0x00};
    byte[] LE_INCORRECT = new byte[]{(byte) 0x6C, (byte) 0x00};
    byte[] AID_LID_INCONNU = new byte[]{(byte) 0x6A, (byte) 0x82};
    byte[] ETAT_NON_CONFORME = new byte[]{(byte) 0x69, (byte) 0x86};
    byte[] P1_P2_INCORRECT_SELECT = new byte[]{(byte) 0x6A, (byte) 0x86};
    byte[] P1_P2_INCORRECT_READ_UPDATE = new byte[]{(byte) 0x6B, (byte) 0x00};
    byte[] OFFSET_LC_INCORRECT = new byte[]{(byte) 0x6A, (byte) 0x87};
    byte[] OFFSET_LE_INCORRECT = new byte[]{(byte) 0x6C, (byte) 0x00};
    byte[] RETOUR_OK = new byte[]{(byte) 0x90, (byte) 0x00};

    byte[] SELECT_APPLICATION_AID = new byte[]{(byte) 0xD2,
            (byte) 0x76, (byte) 0x00, (byte) 0x00, (byte) 0x85, (byte) 0x01, (byte) 0x01};
    byte[] CC_FILE_ID = new byte[]{(byte) 0xE1, (byte) 0x03};
    byte[] FILE_ID = new byte[]{(byte) 0x81, (byte) 0x01};

    int ETAT_SELECT_APP = 0;
    int ETAT_SELECT_FILE = 1;
    int currentState = ETAT_SELECT_APP;

    File ccFile;
    File NDEFFile;
    int NDEFFileSize = -1;
    int selectedFile = 0;

    public cCardService() {
        super();
        String filename = "MyCCFile";
        ccFile = new File(filename);
        if (!ccFile.exists()) {
            try {
                FileOutputStream outputStream = openFileOutput(filename, Context.MODE_PRIVATE);
                outputStream.write(new byte[]{(byte) 0x00, (byte) 0x0F}); // Size
                outputStream.write(new byte[]{(byte) 0x20}); // Map
                outputStream.write(new byte[]{(byte) 0x00, (byte) 0xF0}); // MLe
                outputStream.write(new byte[]{(byte) 0x00, (byte) 0xF0}); // MLc
                outputStream.write(new byte[]{(byte) 0x04, (byte) 0x06,
                        (byte) 0x81, (byte) 0x01,
                        (byte) 0x80, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00}); // TLV
                outputStream.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        filename = "MyNDEFFile";
        NDEFFile = new File(filename);
        try {
            BufferedReader br = new BufferedReader(new FileReader(NDEFFile));
            String line;
            while ((line = br.readLine()) != null) {
                NDEFFileSize += line.length() + 1;
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[] processCommandApdu(final byte[] byAPDU, Bundle extras) {

        byte CLA = byAPDU[0], INS = byAPDU[1];

        if (CLA != 0x00) {
            return CLA_INCONNUE;
        }

        // **********************
        // Process SELECT Command
        // **********************
        if (INS == (byte) 0xA4) {

            byte P1 = byAPDU[2], P2 = byAPDU[3], Lc = byAPDU[4], Le;
            byte[] Data = Arrays.copyOfRange(byAPDU, 5, Lc);
            if (byAPDU.length > Lc)
                Le = byAPDU[1 + Lc];

            if (P1 == (byte) 0x04 && P2 == (byte) 0x00) {

                if (5 > Lc || Lc > 16)
                    return LC_INCORRECT;
                if (!Arrays.equals(Data, SELECT_APPLICATION_AID))
                    return AID_LID_INCONNU;
                currentState = ETAT_SELECT_APP;
                return RETOUR_OK;

            } else if (P1 == (byte) 0x00 && P2 == (byte) 0x0C) {

                if (Lc != 2)
                    return LC_INCORRECT;
                if (Arrays.equals(Data, CC_FILE_ID)) {
                    selectedFile = 1;
                    currentState = ETAT_SELECT_FILE;
                    return RETOUR_OK;
                } else if (Arrays.equals(Data, FILE_ID)) {
                    selectedFile = 2;
                    currentState = ETAT_SELECT_FILE;
                    return RETOUR_OK;
                } else
                    return AID_LID_INCONNU;
            } else

                return P1_P2_INCORRECT_SELECT;
        }

        // ********************
        // Process READ Command
        // ********************
        else if (INS == (byte) 0xB0) {

            byte P1 = byAPDU[2], P2 = byAPDU[3], Le = byAPDU[4];

            if (currentState != ETAT_SELECT_FILE)
                return ETAT_NON_CONFORME;
            if (P1 > (byte) 0x7F)
                return P1_P2_INCORRECT_READ_UPDATE;
            if (Le > (byte) 0xF0)
                return LE_INCORRECT;
            if (P1 * 16 + P2 + Le > NDEFFileSize) // TODO: byte / int comparison ?
                return OFFSET_LE_INCORRECT;

            // TODO: Read file.

            return RETOUR_OK;
        }

        // **********************
        // Process UPDATE Command
        // **********************
        else if (INS == (byte) 0xD6) {

            byte P1 = byAPDU[2], P2 = byAPDU[3], Lc = byAPDU[4];
            byte[] Data = Arrays.copyOfRange(byAPDU, 5, 5 + Lc);

            if (currentState != ETAT_SELECT_FILE)
                return ETAT_NON_CONFORME;
            if (Lc > (byte) 0xF0 || Lc != (byte) Data.length)
                return LC_INCORRECT;
            if (P1 * 16 + P2 + Lc > NDEFFileSize) // TODO: byte / int comparison ?
                return OFFSET_LC_INCORRECT;

            // TODO: Update file.

            return RETOUR_OK;
        } else {
            return INS_INCONNUE;
        }
    }

    @Override
    public void onDeactivated(int reason) {
    }
}
