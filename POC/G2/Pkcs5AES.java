import java.io.*;
import java.util.Random;

public class Pkcs5AES {

    Aes aes=new Aes();
    int k=16;                                   //Taille des blocs AES, nb d'octets max a rajouter pour le bourrage

    byte[] iv = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    } ;

    private byte[] pkcs5(String name){
        try {
            File f =new File(name);
            long length = f.length();
            //System.out.println("Taille du fichier = "+length);
            byte[] paddedFile = new byte[(int) (length+(k-(length%k)))];

            FileInputStream fis = new FileInputStream(f);
            fis.read(paddedFile);

            for(int i=paddedFile.length-1; i>(int) (length+(k-(length%k)));i--){
                paddedFile[i]=0x0c;
            }

            //System.out.println("Taille du fichier bourré = " +paddedFile.length);
            return paddedFile;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] inv_pkcs5(String name){

        File f = new File(name);
        try {
            FileInputStream fis = new FileInputStream(f);
            byte[] tmp = fis.readAllBytes();
            int i;
            for(i =tmp.length-1; tmp[i]==0x00 ;i--){}

            if(i==tmp.length-1){
                System.err.println("Il n'y a pas de bourrage a retirer");
                return null;
            }

            byte[] file = new byte[i+1];
            System.arraycopy(tmp,0,file,0,i+1);
            return file;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] aes_cbc(String name){

        File f = new File(name);
        byte[] paddedFile = pkcs5(name);
        byte[] cryptedFile = new byte[paddedFile.length];
        aes= new Aes();

        //Generation d'un vecteur d'initialisation random
        setRandomIv();

        System.out.println("taille du fichier bourré = "+ paddedFile.length);
        System.out.println("taille du fichier crypté = "+cryptedFile.length);

        //Chiffrement du 1er bloc
        aes.setState(paddedFile,0);
        for(int i=0; i<16;i++){
            aes.State[i]= (byte) (paddedFile[i] ^ iv[i]);
        }
        aes.chiffrer();
        System.arraycopy(aes.State, 0, cryptedFile, 0, 16);

        //Chiffrement des blocs suivants
        for(int i=16; i<paddedFile.length; i+=16){

            aes.setState(paddedFile,i);
            for(int j=0; j<16;j++){
                aes.State[j]= (byte) (aes.State[j] ^ cryptedFile[i-16+j]);
            }
            aes.chiffrer();
            System.arraycopy(aes.State, 0, cryptedFile, i, 16);
        }

        try {

            FileOutputStream fos=new FileOutputStream("POC/G2/cbc-secret.jpg");

            fos.write(iv);
            fos.write(cryptedFile);
            fos.flush();
            fos.close();
            return cryptedFile;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void setRandomIv(){
        Random r = new Random();
        r.nextBytes(iv);

    }

    public void setRandomKey(){
        Random r = new Random();
        r.nextBytes(aes.K);

    }

    public static void main(String[] args) throws IOException {
       /* try {
        Pkcs5AES a = new Pkcs5AES();
        byte[] tmp = a.pkcs5("butokuden.jpg");
        File f = new File("POC/G2/pkcs5-butokuden.jpg");
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(tmp);
        byte[] tmp2 = a.inv_pkcs5("POC/G2/pkcs5-butokuden.jpg");
        fos.write(tmp2);


        } catch (IOException e) {
            e.printStackTrace();
        }*/

        Pkcs5AES a = new Pkcs5AES();
        a.aes_cbc("butokuden.jpg");

    }


}
