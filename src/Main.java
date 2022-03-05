import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {
		Scanner scan = new Scanner(System.in);
		System.out.println("Dobrodosli!");
		System.out.println("1 - registracija");
		System.out.println("2 - prijava");
		int opcija  = scan.nextInt();
		FileSystem fileSystem = new FileSystem();
		if(opcija == 1) {
			fileSystem.registracija();
		}
		else if (opcija == 2) {
			try {
				fileSystem.prijava();
			} catch (InvalidKeyException | NoSuchProviderException | SignatureException e1) {
				e1.printStackTrace();
			}
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		else System.out.println("Nepodrzana opcija, pokusajte ponovo!");
		scan.close();
	}
}
