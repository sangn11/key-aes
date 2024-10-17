package aes;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Controler {
	/**
	 * Mã hóa plainText thành chuỗi được mã hóa
	 * 
	 * @param plainText: chuỗi cần mã hóa
	 * @param k:         key
	 * @param keyBits:   độ dài key
	 * @return chuỗi cipherText được mã hóa
	 */
	public static String encrypt(String plainText, String k, int keyBits) {
		// Mã hóa chuỗi thành mảng byte utf-8
	    byte[] plaintextBytes = Controler.utf8Encode(plainText);
	    byte[] kBytes = Controler.utf8Encode(k);
	    // Số byte của key
	    int nBytes = keyBits / 8;
	    byte[] pwBytes = new byte[nBytes];
	    
	    // Gán các byte của pwBytes bằng các byte của kBytes, nếu kBytes không đủ 16 byte thì gán các byte còn lại bằng 0
	    for (int i = 0; i < nBytes; i++) {
	        pwBytes[i] = i < kBytes.length ? kBytes[i] : 0;
	    }
	    
	    // Mã hóa pwBytes bằng AES và trả về mảng key chứa 16 byte
	    byte[] key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes));
	    byte[] keyConcat = new byte[nBytes];
	    System.arraycopy(key, 0, keyConcat, 0, key.length);
	    System.arraycopy(key, 0, keyConcat, key.length, nBytes - 16);
	    
	    // Lấy thời gian hiện tại trong đơn vị millisecond (1/1000 giây)
	    long timestamp = System.currentTimeMillis();
	    // Lấy phần dư của timestamp khi chia cho 1000 để lấy ra phần millisecond
	    int nonceMs = (int) (timestamp % 1000);
	    // Lấy phần nguyên của timestamp khi chia cho 1000 để lấy ra phần second
	    int nonceSec = (int) (timestamp / 1000);
	    // Random một số nguyên từ 0 đến 0xffff (65535)
	    int nonceRnd = (int) (Math.random() * 0xffff);
	    
	    // Tạo mảng salt chứa 16 byte, 8 byte đầu chứa nonceMs, nonceRnd, nonceSec, 8 byte còn lại chứa 0
	    byte[] salt = {
	        (byte) (nonceMs & 0xff),
	        (byte) ((nonceMs >>> 8) & 0xff),
	        (byte) (nonceRnd & 0xff),
	        (byte) ((nonceRnd >>> 8) & 0xff),
	        (byte) (nonceSec & 0xff),
	        (byte) ((nonceSec >>> 8) & 0xff),
	        (byte) ((nonceSec >>> 16) & 0xff),
	        (byte) ((nonceSec >>> 24) & 0xff),
	        0, 0, 0, 0, 0, 0, 0, 0
	    };
	    
	    byte[] ciphertextBytes = Controler.nistEncryption(plaintextBytes, keyConcat, salt);
	    StringBuilder ciphertextUtf8 = new StringBuilder(ciphertextBytes.length);
	    for (byte bytes : ciphertextBytes) {
	    	ciphertextUtf8.append(Character.toChars(bytes & 0xff));
	    }
	    StringBuilder nonceStr = new StringBuilder(8);
	    for (int i=0; i<8; i++) {
	    	nonceStr.append(Character.toChars(salt[i] & 0xff));
	    }
	    String ciphertextB64 = Controler.base64Encode(nonceStr.toString() + ciphertextUtf8.toString());
	    return ciphertextB64;
	}
	
	/**
	 * Được triển khai để thực hiện mã hóa dữ liệu bằng thuật toán AES (Advanced Encryption Standard) 
	 * theo các quy tắc của Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST)
	 * 
	 * @param plainText: chuỗi cần mã hóa
	 * @param k: key
	 * @param keyBits: độ dài key
	 * @return chuỗi cipherText được mã hóa
	 */
	public static byte[] nistEncryption(byte[] plainText, byte[] key, byte[] salt) {
		// AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)
        int blockSize = 16; 
        // Đếm số block bằng cách lấy độ dài plainText/blockSize (16), sau đó làm tròn lên
        int blockCount = (int) Math.ceil((double) plainText.length / blockSize);
        // Tạo mảng cipherText có số phần tử (byte) bằng số phần tử (byte) của plaintext
        byte[] ciphertext = new byte[plainText.length];
        // Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
        byte[] cipherCntr = AES.cipher(salt, AES.keyExpansion(key));

        // Mã hóa từng block của plainText
        for (int b = 0; b < blockCount; b++) {
            // Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght
            int blockLength = (b < blockCount - 1) ? blockSize : (plainText.length) % blockSize;

            // Các byte của ciphertext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và plaintext
            for (int i = 0; i < blockLength; i++) {
                ciphertext[b * blockSize + i] = (byte) (cipherCntr[i] ^ plainText[b * blockSize + i]);
            }
        }

        return ciphertext;
    }

	
	/**
	 * Giải mã chuỗi được mã hóa thành chuỗi ban đầu
	 * 
	 * @param cipherText: chuỗi cần giải mã
	 * @param k: key
	 * @param keyBits: độ dài key
	 * @return chuỗi plainText được giải mã
	 * */
	public static String decrypt(String cipherText, String k, int keyBits) {
		// Giải mã chuỗi base64 thành chuỗi utf-8
    	String cipher = Controler.base64Decode(cipherText);
    	// Mã hóa chuỗi thành mảng byte utf-8
        byte[] kBytes = Controler.utf8Encode(k);
        int nBytes = keyBits / 8;
        // Số byte của key
        byte[] pwBytes = new byte[nBytes];
        // Gán các byte của pwBytes bằng các byte của kBytes, nếu kBytes không đủ 16 byte thì gán các byte còn lại bằng 0
        for (int i = 0; i < nBytes; i++) {
            pwBytes[i] = i < kBytes.length ? kBytes[i] : 0;
        }
        
        byte[] key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes));
	    byte[] keyConcat = new byte[nBytes];
	    System.arraycopy(key, 0, keyConcat, 0, key.length);
	    System.arraycopy(key, 0, keyConcat, key.length, nBytes - 16);

	    // Lấy salt từ 8 byte đầu của cipher
        byte[] salt = new byte[16];
        for (int i = 0; i < 8; i++) {
            salt[i] = (byte) Character.codePointAt(cipher, i);
        }
        
        // Lấy các byte từ 8 đến cuối của cipher để giải mã
        byte[] encryptedBytes = new byte[cipher.length() - 8];
        for (int i = 8; i < cipher.length(); i++) {
            encryptedBytes[i - 8] = (byte) Character.codePointAt(cipher, i);
        }
        
        byte[] plaintextBytes = Controler.nistDecryption(encryptedBytes, keyConcat, salt);
        String plaintext = Controler.utf8Decode(plaintextBytes);
        return plaintext;
    }
	
	/**
	 * Được sử dụng để giải mã dữ liệu được mã hóa bằng thuật toán AES (Advanced Encryption Standard) 
	 * theo các quy tắc của Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST)
	 * 
	 * @param cipherText: chuỗi cần giải mã
	 * @param k: key
	 * @param keyBits: độ dài key
	 * @return chuỗi plainText được giải mã
	 */
	public static byte[] nistDecryption(byte[] cipherText, byte[] key, byte[] salt) {
		// AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)
		int blockSize = 16;
		// Đếm số block bằng cách lấy độ dài cipherText/blockSize (16), sau đó làm tròn lên
		int blockCount = (int) Math.ceil((double) cipherText.length / blockSize);
		// Tạo mảng plainText có số phần tử (byte) bằng số phần tử (byte) của cipherText
		byte[] plainText = new byte[cipherText.length];
		// Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
		byte[] cipherCntr = AES.cipher(salt, AES.keyExpansion(key));
		
		// Mã hóa từng block của cipherText
		for (int b = 0; b < blockCount; b++) {
			// Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext 
			// để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght 
			int blockLength = (b < blockCount - 1) ? blockSize : (cipherText.length % blockSize);
			// Các byte của plaintext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và ciphertext
			for (int i = 0; i < blockLength; i++) {
                plainText[b * blockSize + i] = (byte) (cipherCntr[i] ^ cipherText[b * blockSize + i]);
            }
		}
		return plainText;
	}
	
	/**
	 * Mã hóa chuỗi thành mảng byte utf-8
	 */
	public static byte[] utf8Encode(String str) {
        try {
            // Trả về các giá trị Unicode đại diện cho một chuỗi được mã hóa utf-8
            // Ví dụ: "Đại học" -> 196,144,225,186,161,105,32,104,225,187,141,99
            return str.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Nếu không có hỗ trợ mã hóa UTF-8
            try {
                return str.getBytes("UTF-8");
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
    }
	
	/**
	 * Mã hóa chuỗi thành mảng byte utf-8
	 */
	public static String utf8Decode(byte[] bytes) {
        try {
            // Giải mã các byte được mã hóa utf-8 thành chuỗi
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Nếu không có hỗ trợ giải mã UTF-8
            try {
                return new String(bytes, "UTF-8");
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
    }
	
	/**
	 * Mã hóa chuỗi thành chuỗi base64
	 * */
	public static String base64Encode(String str) {
        try {
            // Mã hóa chuỗi thành Base64
            return Base64.getEncoder().encodeToString(str.getBytes());
        } catch (Exception e) {
            throw new Error("No Base64 Encode");
        }
    }
	
	/**
	 * Giải mã chuỗi base64 thành chuối ký tự ban đầu
	 * */
	public static String base64Decode(String str) {
        try {
            // Giải mã chuỗi Base64 thành chuỗi ký tự ban đầu
            return new String(Base64.getDecoder().decode(str));
        } catch (Exception e) {
            throw new Error("No Base64 Decode");
        }
    }
}
