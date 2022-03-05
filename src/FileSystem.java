import java.awt.Desktop;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FileUtils;

public class FileSystem {

	private String username;
	private String usernameHash;
	private String passwordHash;
	private String salt;
	private static final Scanner scan = new Scanner(System.in);
	private boolean prijavljen = false;
	private static final String USERS_PATH = "./users";
	private static final String SHARED_DIR = "./shared dir";
	private static final String CERTS_DIR = "./certs";
	private static final String KEYS_PATH = "./keys";
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private X509Certificate certificate;
	private X509Certificate caCertificate;
	private X509CRL crl;
	private String certificatePath;
	private static final String CA_PATH = "certs\\ca.crt";
	private static final String CRL_PATH = "crl\\crl.pem";
	
	public void registracija() {
		try {
			System.out.println("Unesite korisnicko ime: ");
			String username = scan.nextLine();
			usernameHash = CriptoUtil.hashText(username);
			System.out.println("Unesite lozinku: ");
			salt = CriptoUtil.getNextSalt();
			passwordHash = CriptoUtil.hashText(scan.nextLine() + salt);
			
			BufferedReader br = new BufferedReader(new FileReader("korisnici.txt"));
			String s = "";
			boolean postoji = false;
			while((s = br.readLine()) != null) {
				if(s.startsWith(usernameHash)) {
					postoji = true;
					break;
				}
			}
			
			if(postoji) {
				System.out.println("Korisnik je vec registrovan!");
				br.close();
			}
			else {
				System.out.println("Uspjesna registracija!");
				createHomeDirectory(username);
			}
			
			FileWriter fw = new FileWriter("korisnici.txt", true);
			PrintWriter bw = new PrintWriter(new BufferedWriter(fw));
			bw.println(usernameHash + "#" + passwordHash + "#" + salt);
			bw.close();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void prijava() throws InvalidKeyException, NoSuchProviderException, SignatureException {
		System.out.println("Unesite korisnicko ime: ");
		try {
			username = scan.nextLine();
			usernameHash = CriptoUtil.hashText(username); 
			System.out.println("Unesite lozinku: ");
			String password = scan.nextLine();
			BufferedReader br = new BufferedReader(new FileReader("korisnici.txt"));
			String s = "";
			
			certificatePath = CERTS_DIR + File.separator + username + "Cert.crt";
			
			while((s = br.readLine()) != null) {
				if(s.startsWith(usernameHash)) {
					String[] parametri = s.split("#");
					String passwordHashProvjera = CriptoUtil.hashText(password + parametri[2]);
					certificate = CriptoUtil.loadCertificate(certificatePath);
					caCertificate = CriptoUtil.loadCertificate(CA_PATH);
					crl = CriptoUtil.loadCRL(CRL_PATH);
					boolean validCert = CriptoUtil.checkCertificate(certificate, caCertificate, crl);					
					try {
						if(passwordHashProvjera.equals(parametri[1]) && validCert) {
							String keyPath = KEYS_PATH + File.separator + username + "PrivateKey.pk8";
							privateKey = CriptoUtil.loadPrivateKey(keyPath);
							publicKey = certificate.getPublicKey();
							prijavljen = true;
							break;
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			if(prijavljen) {
				System.out.println("Uspjesna prijava!");
				listDirectory(username);
				performFunction(username);
				File dir = new File(USERS_PATH + File.separator + username);
				File[] files = dir.listFiles();
				for(File f : files) {
					if(f.getName().contains("Dec") || f.getName().contains("Decr"))
						f.delete();
				}
				File dir2 = new File(SHARED_DIR);
				File[] files2 = dir2.listFiles();
				for(File f : files2) {
					if(f.getName().contains("Dec") || f.getName().contains("Decr"))
						f.delete();
				}
			}
			else{
				System.out.println("Neuspjesna prijava!");
			}
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void performFunction(String username) {
		System.out.println();
		System.out.print(username + ">> ");
		String option = "";
		while(!"quit".equals(option = scan.nextLine())) {
			System.out.print(username + ">> ");
			if(option.startsWith("create")) {
				String[] parametri = option.split(" ");
				String sadrzaj = "";
				for(int i = 2; i < parametri.length; i++)
					sadrzaj += parametri[i] + " ";
				createFile(parametri[1], sadrzaj, username);
				System.out.print(username + ">> ");
			}
			else if(option.startsWith("open")) {
				open(option.split(" ")[1], username, option.split(" ")[2]);
			}
			else if(option.startsWith("upload")) {
				String source = option.split(" ")[1];
				String destination = option.split(" ")[2];
				try {
					upload(source, destination, username);
				} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException
						| NoSuchPaddingException | InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				}
			}
			else if(option.startsWith("download")) {
				String source = option.split(" ")[1];
				String destination = option.split(" ")[2];
				try {
					download(source, destination, username);
				} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
						| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
						| SignatureException e) {
					e.printStackTrace();
				}
			}
			else if(option.startsWith("edit")) {
				String[] parametri = option.split(" ");
				String fileName = parametri[1];
				String additionalContent = "";
				for(int i = 2; i < parametri.length; i++)
					additionalContent += parametri[i] + " ";
				try {
					edit(fileName, additionalContent, username);
				} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
						| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException
						| InvalidKeySpecException e) {
					e.printStackTrace();
				}
			}
			else if(option.startsWith("delete")) {
				delete(option.split(" ")[1], username);
				System.out.print(username + ">> ");
			}
			else if(option.startsWith("send")) {
				String[] params = option.split(" ");
				try {
					send(params[1], params[2]);
				} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
						| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException
						| CertificateException | InvalidKeySpecException | IOException e) {
					e.printStackTrace();
				}
			}
			else System.out.println("Nepodrzana opcija!");
		}
		prijavljen=false;
	}
	
	public void createFile(String fileName, String content, String username) {
		File file = new File(USERS_PATH + File.separator + username + File.separator + fileName);
		String parametri[] = fileName.split("\\.");
		String fileNameOut = parametri[0] + "Enc." + parametri[1];
		File fileEnc = new File(USERS_PATH + File.separator + username + File.separator + fileNameOut);
		try {
			if(file.createNewFile()) {
				//PrintWriter pw = new PrintWriter(new FileWriter(file));
				//pw.write(content);
				PrintStream pos = new PrintStream(new FileOutputStream(file));
				pos.write(content.getBytes());
				pos.close();
				BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(content.getBytes("UTF-8")));
				byte[] signature = CriptoUtil.signature(privateKey, bis);
				CriptoUtil.encrypt(signature, publicKey, certificatePath, file, fileEnc, "DES");
				System.out.println("Fajl kreiran!");
				//pw.close();
				file.delete();
			}
			else System.out.println("Fajl vec postoji!");
		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
	public void open(String fileName, String username, String share) {
		
		if("false".equals(share)) {
			File in = new File(USERS_PATH + File.separator + username + File.separator + fileName);
			String s = fileName.replace("Enc", "Dec");
			File out = new File(USERS_PATH + File.separator + username + File.separator + s);
			Desktop desktop = Desktop.getDesktop();
			if(in.exists()) {
				try {
					CriptoUtil.decrypt(privateKey, in, out, "DES");
					//in.delete();
					desktop.open(out);
				} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
					e.printStackTrace();
				}
			}
			else System.out.println("Fajl ne postoji!");
		}
		else if("true".equals(share)){
			File in = new File(SHARED_DIR + File.separator + fileName);
			String s = fileName.replace("Enc", "Dec");
			File out = new File(SHARED_DIR + File.separator + s);
			Desktop desktop = Desktop.getDesktop();
			if(in.exists()) {
				try {
					String keyPath = KEYS_PATH + File.separator + username + "PrivateKey.pk8";
					PrivateKey privateKeyOther = CriptoUtil.loadPrivateKey(keyPath);
					CriptoUtil.decrypt(privateKeyOther, in, out, "DES");
					//in.delete();
					desktop.open(out);
				} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
					System.out.println("Fajl nije posalt ovom korisniku!");
				}
			}
			else System.out.println("Fajl ne postoji!");
		}
	}
	
	public void upload(String source, String destination, String username) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		File sourceFile = new File(source);
		File destinationFile = new File(USERS_PATH + File.separator + destination);
		String[] params = source.split("\\.");
		String s = params[0] + "Enc." + params[1];
		File sourceFileEnc = new File(s);
		try {
			byte[] content = Files.readAllBytes(sourceFile.toPath());
			
			BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(content));
			byte[] signature = CriptoUtil.signature(privateKey, bis);
			CriptoUtil.encrypt(signature, publicKey, certificatePath, sourceFile, sourceFileEnc, "DES");
			FileUtils.copyFileToDirectory(sourceFileEnc, destinationFile);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void download(String source, String destination, String username) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		File sourceFile = new File(USERS_PATH + File.separator + username + File.separator + source);
		File destinationFile = new File(destination);
		String s = sourceFile.getName().replace("Enc", "");
		File sourceFileDec = new File(USERS_PATH + File.separator + username + File.separator + s);
		try {
			CriptoUtil.decrypt(privateKey, sourceFile, sourceFileDec, "DES");
			FileUtils.copyFileToDirectory(sourceFileDec, destinationFile);
		} catch (IOException e) {
			e.printStackTrace();
		}
		sourceFileDec.delete();
	}
	
	@SuppressWarnings("deprecation")
	public void edit(String fileName, String additionalContent, String username) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeySpecException {
		File file = new File(USERS_PATH + File.separator + username + File.separator + fileName);
		String s = file.getName().replace("Enc", "");
		File fileDec = new File(USERS_PATH + File.separator + username + File.separator + s);
		String[] params = fileDec.getName().split("\\.");
		String str = params[0] + "Encr." + params[1];
		File fileEnc = new File(USERS_PATH + File.separator + username + File.separator + str);
		try {
			CriptoUtil.decrypt(privateKey, file, fileDec, "DES");
			//file.delete();
			FileUtils.writeStringToFile(fileDec, additionalContent, true);
			//System.out.println(new String(Files.readAllBytes(fileDec.toPath())));
			byte[] content = Files.readAllBytes(fileDec.toPath());
			BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(content));
			byte[] signature = CriptoUtil.signature(privateKey, bis);
			CriptoUtil.encrypt(signature, publicKey, certificatePath, fileDec, fileEnc, "DES");
//			System.out.println(file.toString());
//			System.out.println(fileDec.toString());
//			System.out.println(fileEnc.toString());
			file.delete();
			fileDec.delete();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void send(String fileName, String username) throws InvalidKeyException, InvalidAlgorithmParameterException, 
		NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException, CertificateException, InvalidKeySpecException {
		
		File file = new File(USERS_PATH + File.separator + this.username + File.separator + fileName);
		String s = "";
		if(file.getName().contains("Enc") && !file.getName().contains("Encr"))
			s = file.getName().replace("Enc", "");
		else if(file.getName().contains("Encr"))
			s = file.getName().replace("Encr", "");
		File fileDec = new File(USERS_PATH + File.separator + this.username + File.separator + s);
		CriptoUtil.decrypt(privateKey, file, fileDec, "DES");
		
		X509Certificate usernameCert = CriptoUtil.loadCertificate(CERTS_DIR + File.separator + username + "Cert.crt");
		PublicKey publicKeyOther = usernameCert.getPublicKey();
		
		String[] params = fileDec.getName().split("\\.");
		String str = params[0] + "Enc." + params[1];
		File fileEnc = new File(SHARED_DIR + File.separator + str);
		byte[] content = Files.readAllBytes(fileDec.toPath());
		BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(content));
		byte[] signature = CriptoUtil.signature(privateKey, bis);
		CriptoUtil.encrypt(signature, publicKeyOther, certificatePath, fileDec, fileEnc, "DES");
		fileDec.delete();
	}
	
	public void delete(String fileName, String username) {
		File file = new File(USERS_PATH + File.separator + username + File.separator + fileName);
		if(file.exists()) {
			file.delete();
			System.out.println("Fajl obrisan!");
		}
		else System.out.println("Fajl ne postoji");
	}
	
	public void listDirectory(String username) {
		System.out.println();
		System.out.println(">> " + username);
		listDirectoryRecursion(new File(USERS_PATH + File.separator + username), 1);
	}
	
	public void listDirectoryRecursion(File fileName, int depth) {
		File[] files = fileName.listFiles();
		
		for(File f : files) {
			for(int i = 0; i < depth; i++)
				System.out.print("\t");
			if(f.isDirectory()) {
				System.out.println("<DIR>" + f.getName());
			}
			else System.out.println(f.getName());
			
			if(f.isDirectory()){
				listDirectoryRecursion(new File(fileName, f.getName()), depth+1);
			}
		}
	}
	
	public void createHomeDirectory(String s) {
		File f = new File(USERS_PATH + File.separator + s);
		if(!f.exists()) {
			f.mkdir();
		}
		else System.out.println("Direktorijum vec postoji!");
	}
	
	public String getUsernameHash() {
		return usernameHash;
	}
	
	public String getPasswordHash() {
		return passwordHash;
	}

	public String getSalt() {
		return salt;
	}
	
}
