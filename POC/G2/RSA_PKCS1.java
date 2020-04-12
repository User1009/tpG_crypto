import java.math.BigInteger;
import java.util.Random;

public class RSA_PKCS1 {

    BigInteger n;
    BigInteger e ;
    BigInteger d ;
    byte[] em = new byte[128];
    String ihash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // sha1sum de ""
    BigInteger x;
    BigInteger cryptedInteger=new BigInteger("0");


    public void createKeys(BigInteger n, BigInteger e){

        System.out.println("Module          (n): " + n + " ("+n.bitLength()+" bits)");
        System.out.println("Exposant public (e): " + e + " ("+e.bitLength()+" bits)");
        this.n=n;
        this.e=e;

    }

    public void createEmTab(byte[] m){

        em[0]=0x00;
        em[1]=0x02;
        Random r = new Random();
        for(int i=2; i<em.length-m.length;i++){
            int tmp=r.nextInt(255);
            em[i]= (byte) (tmp+1);
            System.out.print(String.format("%02x",em[i])+" ");
        }

        for(int i= 0;i<16;i++){
            em[i+ em.length - m.length]= m[i];
        }

    }

    void cryptMessage(byte[] byteMsg){

        createEmTab(byteMsg);
        BigInteger msg = new BigInteger(1, em);          // Encodage du message
        System.out.println("x = " +  x  + " (en décimal)");
        // Affichage de x en décimal
        //System.out.println("x = 0x" + String.format("%X", x) + " (en hexadécimal)");
        // Affichage de x en hexadécimal
        //------------------------------------------------------------------
        //  Chiffrement de l'entier représentatif
        //------------------------------------------------------------------
        cryptedInteger = msg.modPow(e, n);
        System.out.println("x^e mod n = " + cryptedInteger + " ("+ cryptedInteger.bitLength()+" bits)");

    }

    void decryptMessage(BigInteger c){

        byte[] chiffre = c.toByteArray();
        if (chiffre[0] == 0) {
            byte[] tmp = new byte[chiffre.length - 1];
            System.arraycopy(chiffre, 1, tmp, 0, tmp.length);
            chiffre = tmp;
        }

        System.out.println("Taille du chiffré :"+chiffre.length);
        System.out.println("Message chiffré    : " + toHex(chiffre) );
        BigInteger code = new BigInteger(chiffre);
        BigInteger codeDéchiffré = code.modPow(d, n);
        byte[] tmp = codeDéchiffré.toByteArray();
        byte[] md=new byte[5];
        for(int i=0;i<5;i++){

            md[i]=tmp[i+ tmp.length - md.length];
            System.out.print(String.format("%02x",md[i])+" ");

        }
    }


    public static void main(String[] args) throws Exception {
        //------------------------------------------------------------------
        //  Construction et affichage de la clef
        //------------------------------------------------------------------
        BigInteger n = new BigInteger(
                                      "00af7958cb96d7af4c2e6448089362"+
                                      "31cc56e011f340c730b582a7704e55"+
                                      "9e3d797c2b697c4eec07ca5a903983"+
                                      "4c0566064d11121f1586829ef6900d"+
                                      "003ef414487ec492af7a12c34332e5"+
                                      "20fa7a0d79bf4566266bcf77c2e007"+
                                      "2a491dbafa7f93175aa9edbf3a7442"+
                                      "f83a75d78da5422baa4921e2e0df1c"+
                                      "50d6ab2ae44140af2b", 16);
        BigInteger e = BigInteger.valueOf(0x10001);
        BigInteger d = new BigInteger(
                                      "35c854adf9eadbc0d6cb47c4d11f9c"+
                                      "b1cbc2dbdd99f2337cbeb2015b1124"+
                                      "f224a5294d289babfe6b483cc253fa"+
                                      "de00ba57aeaec6363bc7175fed20fe"+
                                      "fd4ca4565e0f185ca684bb72c12746"+
                                      "96079cded2e006d577cad2458a5015"+
                                      "0c18a32f343051e8023b8cedd49598"+
                                      "73abef69574dc9049a18821e606b0d"+
                                      "0d611894eb434a59", 16);

        System.out.println("Module          (n): " + n + " ("+n.bitLength()+" bits)");
        System.out.println("Exposant public (e): " + e + " ("+e.bitLength()+" bits)");
        System.out.println("Exposant privé  (d): " + d + " ("+d.bitLength()+" bits)");
        
        //------------------------------------------------------------------
        //  Construction et affichage du message clair
        //------------------------------------------------------------------
        byte[] m = { 0x4B, 0x59, 0x4F, 0x54, 0x4F } ;
        System.out.println("Message clair      : " + toHex(m) );

        //------------------------------------------------------------------
        //  Construction du tableau em
        //------------------------------------------------------------------

        /*byte[] em = new byte[128];
        em[0]=0x00;
        em[1]=0x02;

        Random r = new Random();


        for(int i=2; i<em.length-m.length;i++){

            int tmp=r.nextInt(255);
            em[i]= (byte) (tmp+1);
            System.out.print(String.format("%02x",em[i])+" ");

        }


        for(int i= 0;i<5;i++){
            em[i+ em.length - m.length]= m[i];
        }

*/
        //------------------------------------------------------------------
        //  Du message m à l'entier représentatif x (partie à modifier)
        //------------------------------------------------------------------
       /* BigInteger x = new BigInteger(1, em);          // Encodage du message
        System.out.println("x = " +  x  + " (en décimal)");
        // Affichage de x en décimal
        System.out.println("x = 0x" + String.format("%X", x) + " (en hexadécimal)");
                                            // Affichage de x en hexadécimal
        //------------------------------------------------------------------
        //  Chiffrement de l'entier représentatif
        //------------------------------------------------------------------
        BigInteger c = x.modPow(e, n);
        System.out.println("x^e mod n = " + c + " ("+c.bitLength()+" bits)");*/

        //------------------------------------------------------------------
        //  Décodage de l'entier représentatif
        //------------------------------------------------------------------
       /* byte[] chiffré = c.toByteArray();
        if (chiffré[0] == 0) {
            byte[] tmp = new byte[chiffré.length - 1];
            System.arraycopy(chiffré, 1, tmp, 0, tmp.length);
            chiffré = tmp;
        }

        System.out.println("Taille du chiffré :"+chiffré.length);
        System.out.println("Message chiffré    : " + toHex(chiffré) );
        BigInteger code = new BigInteger(chiffré);
        BigInteger codeDéchiffré = code.modPow(d, n);
        byte[] tmp = codeDéchiffré.toByteArray();
        byte[] md=new byte[5];
        for(int i=0;i<5;i++){

            md[i]=tmp[i+ tmp.length - md.length];
            System.out.print(String.format("%02x",md[i])+" ");

        }*/

    }
    
    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) sb.append(String.format("0x%02X ", k));
        sb.append(" (").append(données.length).append(" octets)");
        return sb.toString();
    }
}

/*
  $ make
  javac *.java 
  $ java RSA_PKCS1
  Module          (n): 12322204109610601400...299   (1024 bits)
  Exposant public (e): 65537 (17 bits)
  Exposant privé  (d): 37767385438721355925...209   (1022 bits)
  Message clair      : 0x4B 0x59 0x4F 0x54 0x4F     (5 octets)
  x = 323620918351 (en décimal)
  x = 0x4B594F544F (en hexadécimal)
  x^e mod n = 65891982980551359715048403549...638   (1023 bits)
  Message chiffré    : 0x5D 0xD5 0x53 0x0B ... 0x26 (128 octets)
*/

/* Test avec un message légèrement différent
  $ make
  javac *.java 
  $ java RSA_PKCS1
  Module          (n): 12322204109610601400...299    (1024 bits)
  Exposant public (e): 65537 (17 bits)
  Exposant privé  (d): 37767385438721355925...209    (1022 bits)
  Message clair      : 0x3B 0x59 0x4F 0x54 0x4F      (5 octets)
  x = 254901441615 (en décimal)
  x = 0x3B594F544F (en hexadécimal)
  x^e mod n = 99064005127797152176285166470...427    (1024 bits)
  Message chiffré    : 0x00 0x8D 0x12 0x63 ... 0xB3  (129 octets)
*/
