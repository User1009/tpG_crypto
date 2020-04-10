import java.io.*;

public class Pkcs5AES {

    Aes aes;
    int k=16;                                   //Taille des blocs AES, nb d'octets max a rajouter pour le bourrage


    private byte[] pkcs5(String name){
        try {
            File f =new File(name);
            long length = f.length();
            System.out.println("Taille du fichier = "+length);
            byte[] file = new byte[(int) (length+(k-(length%k)))];

            FileInputStream fis = new FileInputStream(f);
            fis.read(file);

            for(int i=file.length-1; i>(int) (length+(k-(length%k)));i--){
                file[i]=0x0c;
            }
            return file;
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

    private void aes_cbc(String name){

        File f = new File(name);
        byte[] tmp = pkcs5(name);
        aes= new Aes();

        aes.setState(tmp,0);
        for(int i=0; i<16;i++){
            aes.State[i]= (byte) (aes.State[i] ^ aes.iv[i]);
        }
        aes.chiffrer();
        for(int i=0; i<16;i++){
            tmp[i]=aes.State[i];
        }

        for(int i=16;i<tmp.length;i+=16){

            for(int j=0; j<16;j++){
                aes.State[j]= (byte) (aes.State[j] ^ tmp[i+j]);
            }
            aes.chiffrer();
            for(int j=0; j<16;j++){
                tmp[i+j]=aes.State[j];
            }
        }
        try {
            FileOutputStream fos=new FileOutputStream("cbc-secret.jpg");
            fos.write(tmp);

        } catch (IOException e) {
            e.printStackTrace();
        }


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
        byte[] tmp = a.pkcs5("butokuden.jpg");
        File f = new File("POC/G2/pkcs5-tmp.jpg");
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(tmp);
        a.aes_cbc("POC/G2/pkcs5-tmp.jpg");

    }


}
