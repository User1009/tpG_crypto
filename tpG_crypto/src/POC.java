import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class POC {

    private BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f414918b7d13513ca1110ed80bd2532f8a7aab0314bf54fcaf621eda74263faf2a5921ffc515097a3c556bf86f2048a3c159fccfee6d916d38f7f23f21",16);
    private BigInteger e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06861ef9850e26d1456280523319021062c8743544877923fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c821cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc17e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb623ad507d6b246a1f0c3cc419f155",16);

    private SecretKey k_aes;
    private IvParameterSpec iv;
    private PublicKey publicKey_rsa;

    private byte[] chiffre;

    private void gen_aes_key () {
        KeyGenerator keyGen;
        SecretKey secretKey=null;

        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            k_aes = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void gen_iv(){
        SecureRandom random = new SecureRandom();
        byte[] buffer = new byte[16];
        random.nextBytes(buffer);
        iv = new IvParameterSpec(buffer);
    }

    private void gen_rsa_key(){
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec specPub = new RSAPublicKeySpec(n,e);
            publicKey_rsa = keyFactory.generatePublic(specPub);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
            e1.printStackTrace();
        }
    }

    private void rsa_encrypt(){
        try {
            Cipher chiffreur = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            chiffreur.init(Cipher.ENCRYPT_MODE,publicKey_rsa);
            chiffre = chiffreur.doFinal(k_aes.getEncoded());

            FileOutputStream outputStream = new FileOutputStream("resultat.txt");
            System.out.println("message encrypté : 0x" + chiffre.length + Arrays.toString(chiffre));
            CipherOutputStream cos = new CipherOutputStream(outputStream,chiffreur);
            for (byte b : chiffre) cos.write(b);
            //cos.write(chiffre);
            /*final PrintWriter pw = new PrintWriter(cos);
            pw.flush();
            cos.write(iv.getIV());
            pw.close();*/
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    public static void main(String[] args) {
        POC poc = new POC();
        poc.gen_aes_key();
        poc.gen_iv();
        poc.gen_rsa_key();
        poc.rsa_encrypt();
    }

}
