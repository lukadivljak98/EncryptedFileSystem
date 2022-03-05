import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;

public class CriptoUtil {
	
	private static final Random RANDOM = new SecureRandom();
	
	public static String hashText(String s) throws NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] input = s.getBytes();
		byte[] output = messageDigest.digest(input);
		
		return Hex.toHexString(output);
	}
	
	public static String getNextSalt() {
		byte[] salt = new byte[16];
		RANDOM.nextBytes(salt);
		return Hex.toHexString(salt);
	}
	
	public static void encrypt(byte[] signature, PublicKey publicKey, String certPath, File in, File out, String algorithm) 
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException
	{
		FileInputStream fis = new FileInputStream(in);
		FileOutputStream fos = new FileOutputStream(out);
		
		KeyGenerator keyGenerator = null;
		Cipher cipher = null;
		byte[] ivBytes = null;
		
		if("DES".equals(algorithm)) {
			keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(168);
			ivBytes = new byte[8];
			cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		}
		else if("AES".equals(algorithm)) {
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			ivBytes = new byte[16];
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		}
		
		new SecureRandom().nextBytes(ivBytes);
		SecretKey key = keyGenerator.generateKey();
		
		byte[] encKey = key.getEncoded();
		byte[] encPath = certPath.getBytes();
		byte[] buffer = concat(ivBytes, encKey, encPath);  
		
		//System.out.println(new String(ivBytes));
		//System.out.println(new String(encKey));
		//System.out.println(new String(encPath));
		
		byte[] zaglavlje = null;
		zaglavlje = rsaEncrypt(buffer, publicKey);
		
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		
		//PrintStream ps = new PrintStream(new BufferedOutputStream(fos));
		//System.out.println(new String(zaglavlje));
		//System.out.println(new String(signature));
		fos.write(zaglavlje);
		fos.write(signature);
		//fos.write(content.getBytes());
		//ps.close();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		CipherInputStream cis = new CipherInputStream(fis, cipher);
		//ps = new PrintStream(new BufferedOutputStream(new FileOutputStream(in, true)));
		write(cis, fos);
		//ps.close();
		fis.close();
	}
	
	
	public static void decrypt(PrivateKey privateKey, File in, File out, String algorithm) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		FileInputStream fis = new FileInputStream(in);
		FileOutputStream fos = new FileOutputStream(out);
		
		byte[] buffer = new byte[256];
		fis.read(buffer);
		
		byte[] zaglavlje = rsaDecrypt(buffer, privateKey);
		
		KeyGenerator keyGenerator = null;
		Cipher cipher = null;
		byte[] ivBytes = null;
		byte[] keyBytes = null;
		
		if("DES".equals(algorithm)) {
			//keyGenerator = KeyGenerator.getInstance("DESede");
			//keyGenerator.init(168);
			keyBytes = new byte[24];
			ivBytes = new byte[8];
			cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		}
		else if("AES".equals(algorithm)) {
			//keyGenerator = KeyGenerator.getInstance("AES");
			//keyGenerator.init(256);
			keyBytes = new byte[32];
			ivBytes = new byte[16];
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		}
		
		int i = 0;
		int j = 0;

		for(;j<ivBytes.length;)
			ivBytes[j++] = zaglavlje[i++];

		j = 0;
		for(;j<keyBytes.length;)
			keyBytes[j++] = zaglavlje[i++];

		j = 0;
		byte[] certPath = new byte[zaglavlje.length-i];

		for(;j<certPath.length;) 
			certPath[j++] = zaglavlje[i++];
		
		//System.out.println(new String(ivBytes));
		//System.out.println(new String(keyBytes));
		//System.out.println(new String(certPath));
		
		SecretKey key = null;
		if(algorithm.equals("AES")) {
			key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
		} else if(algorithm.equals("DES")){
			key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "DESede");
		}
		
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		
		byte[] signature = new byte[256];
		fis.read(signature);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);
		write(fis, cos);
		fos.close();
	}
	
	public static void write(InputStream in, OutputStream out) throws IOException {
		byte[] buffer = new byte[64];
		int numOfBytesRead;
		while((numOfBytesRead = in.read(buffer)) != -1) {
			//System.out.println(numOfBytesRead);
			out.write(buffer, 0, numOfBytesRead);
		}
		out.close();
		in.close();
	}
	
	public static byte[] concat(byte[] array1, byte[] array2, byte[] array3){
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		try {
			outputStream.write(array1);
			outputStream.write(array2);
			outputStream.write(array3);
		}catch(IOException e) {
			e.printStackTrace();
		}
		
		byte[] result = outputStream.toByteArray();
		
		return result;
	}
	
	public static boolean checkCertificate(X509Certificate cert, X509Certificate caCert, X509CRL crl){
		
		try {
			cert.checkValidity();
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			return false;
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			return false;
		}
		
		try {
			cert.verify(caCert.getPublicKey());
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			e.printStackTrace();
			return false;
		}
		
		try {
			crl.verify(caCert.getPublicKey());
			X509CRLEntry crlEntry = crl.getRevokedCertificate(cert);
			crlEntry.getRevocationReason();
			System.out.println("Sertifikat je povucen");
			return false;
		} catch (InvalidKeyException | NoSuchProviderException | SignatureException | CRLException | NoSuchAlgorithmException | NullPointerException e) {}
		
		return true;
	}
	
	public static byte[] signature(PrivateKey privateKey, InputStream is) {

		int numOfBytesRead = 0;
		byte[] buffer = new byte[256];
		Signature signer = null;
		try {
			signer = Signature.getInstance("SHA256withRSA");
		}catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] signatureBytes = new byte[256];
		
		try {
			signer.initSign(privateKey);
		
			while((numOfBytesRead = is.read(buffer)) !=- 1) {
				signer.update(buffer, 0, numOfBytesRead);
				buffer = new byte[256];
			}
		
			signatureBytes = signer.sign();
		}catch(InvalidKeyException | IOException | SignatureException e) {
			e.printStackTrace();
		}
		
		return signatureBytes;
	}

	public static PrivateKey loadPrivateKey(String path) {
	
		StringBuilder keyString = new StringBuilder();
		try{
			 List<String> list = Files.readAllLines((new File(path)).toPath());
			 for(String l : list) {
				 keyString.append(l);
			 }
		}catch(IOException e) {
			e.printStackTrace();
		}
		//System.out.println("LUKA"+keyString);
		
		String del = "-----BEGIN PRIVATE KEY-----";
		keyString.replace(keyString.indexOf(del), keyString.indexOf(del)+del.length(), "");
		del = "-----END PRIVATE KEY-----";
		keyString.replace(keyString.indexOf(del), keyString.indexOf(del)+del.length(), "");
		
		byte[] keyBytes = Base64.decode(keyString.toString());
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = null;
		try{
			keyFactory = KeyFactory.getInstance("RSA");
		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		PrivateKey privateKey = null;
		try{
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		}catch(InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
}	
	
	public static X509Certificate loadCertificate(String certificatePath) {
		
		CertificateFactory cf = null;
		FileInputStream fis = null;
		X509Certificate certificate = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			fis = new FileInputStream(certificatePath);
			certificate = (X509Certificate) cf.generateCertificate(fis);
		}catch(FileNotFoundException | CertificateException e) {
			e.printStackTrace();
		}
		
		return certificate;
	}

	public static X509CRL loadCRL(String CRLPath) {
		
		CertificateFactory cf = null;
		FileInputStream fis = null;
		X509CRL crl = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			fis = new FileInputStream(CRLPath);
			crl = (X509CRL) cf.generateCRL(fis);
		}catch(CertificateException | CRLException | FileNotFoundException e) {
			e.printStackTrace();
		}
		
		return crl;
	}
	
	public static byte[] rsaEncrypt(byte[] txt, PublicKey publicKey) {

		Cipher rsaCipher = null;
		try {
			rsaCipher = Cipher.getInstance("RSA");
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		
		byte[] cipherTxt = null;
		try {
			rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			cipherTxt = rsaCipher.doFinal(txt);
		}catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return cipherTxt;
	}

	public static byte[] rsaDecrypt(byte[] cipherTxt, PrivateKey privateKey) {

		Cipher rsaCipher = null;
		try {
			rsaCipher = Cipher.getInstance("RSA");
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		
		byte[] txt = null;
		try {
			rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
			txt = rsaCipher.doFinal(cipherTxt);
		}catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
			
		return txt;
	}
	
}
