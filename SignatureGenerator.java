package org.apache.commons.test2;
import java.io.ObjectStreamException;
import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.commons.codec.binary.Base64;

public class SignatureGenerator {

    public static void main(String[] args) {
        SignatureGenerator generator = new SignatureGenerator();

        String consumerId = "f68f212e-b470-4be6-8958-76fd2c00c5d2";
        String priviateKeyVersion = "1";
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkFqS1RECoVRV+\n" + 
        		"ZoHOsTn+Hw58HE7gSL9ziKEbCwBqaXcfd3mANXVGR/VePis9aMZfh8Zs0s4b3iQT\n" + 
        		"QVE1JbkE0pieIkJwAoKBomTkWqsYgu2uvXv+H61Fo2e9t8/wSNEfZCOHYh5ICk39\n" + 
        		"OV7K4E4ZbGE8X4fAysbkADRMn5hyI4rPR/hAU5V7nQdXeXrfm3gwRflm0jroPrHb\n" + 
        		"EIBsAAGJtBdfi2NOzVoySCuO4orM4R/0YZ/+qwjXW/xz6R0LeuyqwxruNW1c7t27\n" + 
        		"nPQSDkSorVGYjz6Mi0yCOdn8x7W49mI3++CidRjSffdVnLIDcxwLOTNbF34gkI2P\n" + 
        		"Nc1Q/tqLAgMBAAECggEACYJebTrVXGwB4N9j6myO5dE676pcT9cncTSb0YtjrMcL\n" + 
        		"5kDwQ6PVdgs5hwqnStnFlUezEh9tXmQTRyJj6GaVQFhMC+4EV6VtlsGogytV+wer\n" + 
        		"apMEmoePbRe5LV93p38wz1boUDI5ewdN2bz3Z150aDjFsc//eAbIW/I/FamyFfst\n" + 
        		"j+aSLxPe5HBFSKBZbS7nC6MV3Emfih1Da0jx9JAQUOkEg94TLvBBxv/9v2VBiqAz\n" + 
        		"gXY2UzDtV8VZpHQMnul0elS+uPc+zF/pDZgvCIfK36rWOc/w1JLbl/bvqTifUsr3\n" + 
        		"GrTrHNqgsMYvQ9KuY4kdyQBLYLamJHJ0LJH8Il/isQKBgQDQfJ9Zj15mK6/wwGZa\n" + 
        		"/r1J1leuz+mhmgeFb1EoL48jDQM/kaoMjC4sva04q8NekOqp1oiCOIyt7fa8xlCq\n" + 
        		"AvB1w7QuBT6em0nOwVNjHQURfPAtlKmlUUWBdMzpzV9c5lBiC8IXFpQROaMy6JSx\n" + 
        		"RLP+HzDGwCFTKC2bupJkvDMDNwKBgQDJe8Qdbyr5o0sz6vMr6GUbtiFq2c7cuiR3\n" + 
        		"eMybZ075HQWtAq9joiu73NPJiuPLUL2QSsIUG6Ma1LkjhDr0hNQcU38DtkdNxV8h\n" + 
        		"v9UMzCIt8yOaECc05l1fjiGbHGFvYArYBatOwHi4Gc5/RNy3IBxzHNP1XgbTinpb\n" + 
        		"/XlvkSe1TQKBgAowfQ1Af4mYywGGNbpuxsuMCT8G9FEsmP+BgELpiCJbaXQ650ez\n" + 
        		"tjIDlyq04liF1qI0VPmgT+fUQIHbY2fbuurWhMDXCsdvqXzMYAnxCiVfqNFheaUV\n" + 
        		"wsLf9X/bxLRioT0ZfAPq25O38Gz1hwbe57kcxyJ/k2FgDlKVHMCFniyjAoGBAKzb\n" + 
        		"tDuUfohCImjeb9YBwYzuyujDCQix4ktlphTFoylyTsZKAXM3VNIN+N12fUyXbqr2\n" + 
        		"mF9r/pksW9Iuxe22b8wFjnj+z1nXtXBdBkm+cKx/ZtHsfdaStRUf+ZD73lQRT/xZ\n" + 
        		"kMk1s9wut8zUpY+uyvmvh+GA09Z1fdiiNKcVH74ZAoGAG0tQQJ9nwWeslzte0yk8\n" + 
        		"QvphFHI8/VCOORgmayE+HWYJb5w2Wz8rBRIvIUTOtqp+S197h4QB8E5QSpiSlUNu\n" + 
        		"Te2VwMKenvAAhpIbA98qlZtMhjuOrVKuUh4MMypNJrHi/1egalPHChe26G21rmTI\n" + 
        		"a3OYNoZKX/8qXG940c+7K10=";

        long intimestamp = System.currentTimeMillis();

        System.out.println("consumerId: " + consumerId);
        System.out.println("intimestamp: " + intimestamp);

        Map<String, String> map = new HashMap<>();
        map.put("WM_CONSUMER.ID", consumerId);
        map.put("WM_CONSUMER.INTIMESTAMP", Long.toString(intimestamp));
        map.put("WM_SEC.KEY_VERSION", priviateKeyVersion);

        String[] array = canonicalize(map);

        String data = null;

        try {
            data = generator.generateSignature(privateKey, array[1]);
        } catch(Exception e) { }
        System.out.println("Signature: " + data);
    }
    public String generateSignature(String key, String stringToSign) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256WithRSA");

        ServiceKeyRep keyRep = new ServiceKeyRep(KeyRep.Type.PRIVATE, "RSA", "PKCS#8", Base64.decodeBase64(key));

        PrivateKey resolvedPrivateKey = (PrivateKey) keyRep.readResolve();

        signatureInstance.initSign(resolvedPrivateKey);

        byte[] bytesToSign = stringToSign.getBytes("UTF-8");
        signatureInstance.update(bytesToSign);
        byte[] signatureBytes = signatureInstance.sign();

        String signatureString = Base64.encodeBase64String(signatureBytes);

        return signatureString;
    }
    protected static String[] canonicalize(Map<String, String> headersToSign) {
        StringBuffer canonicalizedStrBuffer=new StringBuffer();
        StringBuffer parameterNamesBuffer=new StringBuffer();
        Set<String> keySet=headersToSign.keySet();

        // Create sorted key set to enforce order on the key names
        SortedSet<String> sortedKeySet=new TreeSet<String>(keySet);
        for (String key :sortedKeySet) {
            Object val=headersToSign.get(key);
            parameterNamesBuffer.append(key.trim()).append(";");
            canonicalizedStrBuffer.append(val.toString().trim()).append("\n");
        }
        return new String[] {parameterNamesBuffer.toString(), canonicalizedStrBuffer.toString()};
    }

    class ServiceKeyRep extends KeyRep  {
        private static final long serialVersionUID = -7213340660431987616L;
        public ServiceKeyRep(Type type, String algorithm, String format, byte[] encoded) {
            super(type, algorithm, format, encoded);
        }
        protected Object readResolve() throws ObjectStreamException {
            return super.readResolve();
        }
    }
}