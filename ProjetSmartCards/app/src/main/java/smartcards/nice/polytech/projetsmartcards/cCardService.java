package smartcards.nice.polytech.projetsmartcards;

import android.content.Context;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
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
    byte[] UPDATE_CCFILE_INTERDIT = new byte[]{(byte) 0x69, (byte) 0x85};
    byte[] RETOUR_OK = new byte[]{(byte) 0x90, (byte) 0x00};

    byte[] SELECT_APPLICATION_AID = new byte[]{(byte) 0xD2,
            (byte) 0x76, (byte) 0x00, (byte) 0x00, (byte) 0x85, (byte) 0x01, (byte) 0x01};
    byte[] CC_FILE_ID = new byte[]{(byte) 0xE1, (byte) 0x03};
    byte[] FILE_ID = new byte[]{(byte) 0x81, (byte) 0x01};

    int ETAT_SELECT_APP = 0;
    int ETAT_SELECT_FILE = 1;
    int currentState = ETAT_SELECT_APP;

    File NDEFFile;
    int NDEFFileSize = -1;
    int NDEFFileMaxSize = 4096;
    int selectedFile = 0;

//    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
//
//    public static String bytesToHex(byte[] bytes) {
//        char[] hexChars = new char[bytes.length * 2];
//        for (int j = 0; j < bytes.length; j++) {
//            int v = bytes[j] & 0xFF;
//            hexChars[j * 2] = hexArray[v >>> 4];
//            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
//        }
//        return new String(hexChars);
//    }

    public cCardService() {
        super();
    }

    public void onCreate() {
        File directory = this.getDir("SCProjectDir", Context.MODE_PRIVATE);

        String filename = "MyNDEFFile";
        NDEFFile = new File(directory, filename);
        if (!NDEFFile.exists())
            try {
                NDEFFile.createNewFile();
                FileOutputStream outputStream = openFileOutput(NDEFFile.getName(), Context.MODE_PRIVATE);
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

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

        int CLA = byAPDU[0] & 0xFF, INS = byAPDU[1] & 0xFF;

        if (CLA != 0x00) {
            return CLA_INCONNUE;
        }

        // **********************
        // Process SELECT Command
        // **********************
        if (INS == 0xA4) {

            int P1 = byAPDU[2] & 0xFF, P2 = byAPDU[3] & 0xFF, Lc = byAPDU[4] & 0xFF, Le;
            byte[] Data = Arrays.copyOfRange(byAPDU, 5, 5 + Lc);
            if (byAPDU.length > Lc)
                Le = byAPDU[1 + Lc] & 0xFF;

            if (P1 == 0x04 && P2 == 0x00) {

                if (5 > Lc || Lc > 16)
                    return LC_INCORRECT;
                if (!Arrays.equals(Data, SELECT_APPLICATION_AID))
                    return AID_LID_INCONNU;
                currentState = ETAT_SELECT_APP;
                return RETOUR_OK;

            } else if (P1 == 0x00 && P2 == 0x0C) {

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
        else if (INS == 0xB0) {

            int P1 = byAPDU[2] & 0xFF, P2 = byAPDU[3] & 0xFF, Le = byAPDU[4] & 0xFF;

            if (currentState != ETAT_SELECT_FILE || (selectedFile != 1 && selectedFile != 2))
                return ETAT_NON_CONFORME;
            Log.e("Le SIZE", String.valueOf(Le));

            // Reading CC File
            if (selectedFile == 1) {
                if (P1 > (byte) 0x7F)
                    return P1_P2_INCORRECT_READ_UPDATE;
                if (Le > (byte) 0x0F)
                    return LE_INCORRECT;
                if (P1 * 16 + P2 + Le > 0x0F) // TODO: byte / int comparison ?
                    return OFFSET_LE_INCORRECT;

                byte[] CCFileContent = new byte[]{(byte) 0x00, (byte) 0x0F, (byte) 0x20, (byte) 0x00,
                        (byte) 0xF0, (byte) 0x00, (byte) 0xF0, (byte) 0x04, (byte) 0x06, (byte) 0x81,
                        (byte) 0x01, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00};
                byte[] result = new byte[Le + 2];
                System.arraycopy(CCFileContent, P2, result, 0, Le);
                System.arraycopy(RETOUR_OK, 0, result, Le, 2);
                return result;
            }

            // Reading NDEF File
            else {
                if (P1 > (byte) 0x7F)
                    return P1_P2_INCORRECT_READ_UPDATE;
                if (Le > 0xF0) {
                    return LE_INCORRECT;
                }
                if (P1 * 16 + P2 + Le > NDEFFileSize || P1 * 16 + P2 + Le > 0x7FFF) // TODO: byte / int comparison ?
                    return OFFSET_LE_INCORRECT;

                byte[] result = new byte[Le + 2];
                try {
                    FileInputStream NDEFFileReader = new FileInputStream(NDEFFile);
                    NDEFFileReader.read(result, P1 * 16 + P2, Le);
                } catch (IOException e) {
                    // TODO: can this ever happen ?
                }
                System.arraycopy(RETOUR_OK, 0, result, Le, 2);
                return result;
            }
        }

        // **********************
        // Process UPDATE Command
        // **********************
        else if (INS == 0xD6) {

            int P1 = byAPDU[2] & 0xFF, P2 = byAPDU[3] & 0xFF, Lc = byAPDU[4] & 0xFF;
            byte[] Data = Arrays.copyOfRange(byAPDU, 5, 5 + Lc);

            if (currentState != ETAT_SELECT_FILE || (selectedFile != 1 && selectedFile != 2))
                return ETAT_NON_CONFORME;
            if (selectedFile != 2)
                return UPDATE_CCFILE_INTERDIT;

            if (Lc > 0xF0 || Lc != Data.length)
                return LC_INCORRECT;
            if (P1 * 16 + P2 + Lc > NDEFFileMaxSize) // TODO: byte / int comparison ?
                return OFFSET_LC_INCORRECT;

            // Updating NDEF File
            try {
                FileOutputStream outputStream = openFileOutput(NDEFFile.getName(), Context.MODE_PRIVATE);
                outputStream.write(Data, P1 * 16 + P2, Lc); // TLV
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return RETOUR_OK;
        } else {
            return INS_INCONNUE;
        }
    }

    @Override
    public void onDeactivated(int reason) {
    }
}
