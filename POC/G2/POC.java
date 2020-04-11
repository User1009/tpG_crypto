import java.io.*;
import java.math.BigInteger;

public class POC {

    Pkcs5AES aes=new Pkcs5AES();
    RSA_PKCS1 rsa = new RSA_PKCS1();
    private BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f414918b7d13513ca1110ed80bd2532f8a7aab0314bf54fcaf621eda74263faf2a5921ffc515097a3c556bf86f2048a3c159fccfee6d916d38f7f23f21",16);
    private BigInteger e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06861ef9850e26d1456280523319021062c8743544877923fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c821cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc17e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb623ad507d6b246a1f0c3cc419f155",16);



    void createRandomKeyAndIv(){
        aes.setRandomIv();
        aes.setRandomKey();
    }


    public void cryptAESKey(String name){

        BigInteger key = new BigInteger(aes.aes.K);
        rsa.cryptMessage(key);
        byte[] tmp=aes.aes_cbc(name);
        try {
            FileOutputStream fos=new FileOutputStream("POC/G2/resultat.txt");
            fos.write(rsa.cryptedInteger.toByteArray());
            fos.write(aes.iv);
            fos.write(tmp);
            fos.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        POC p = new POC();
        p.createRandomKeyAndIv();
        p.rsa.createKeys(p.n, p.e);
        p.cryptAESKey("POC/G2/resultat.txt");
    }

}
