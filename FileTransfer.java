import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import java.io.*;
import javax.crypto.*;

public class FileTransfer {

	static Scanner kb = new Scanner(System.in);

	public static void main(String[] args) throws Exception {
		if (args[0].equalsIgnoreCase("makekeys")) {
			makeKeys();
		} else if (args[0].equalsIgnoreCase("server")
				&& args[1].equalsIgnoreCase("private.bin")) {
			server(args[1], args[2]);
		} else if (args[0].equalsIgnoreCase("client")
				&& args[1].equalsIgnoreCase("public.bin")) {
			client(args[1], args[2], args[3]);
		} else {
			System.out.println("Wrong input");
		}
	}

	private static void client(String publickeyfile, String host,
			String portnumber) throws Exception {
		try (Socket socket = new Socket(host, Integer.parseInt(portnumber))) {

			InputStream is = socket.getInputStream();
			OutputStream os = socket.getOutputStream();
			PublicKey publicKey = null;

			publicKey = loadPublicKey(publicKey, publickeyfile);
			SecureRandom random = new SecureRandom();

			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128, random); // for example
			Key wrapKey = keyGen.generateKey();

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, publicKey);
			byte[] wrappedKey = cipher.wrap(wrapKey);
			System.out.print("Enter path: ");
			String filename = kb.nextLine();
			File file = new File(filename);

			if (!file.exists()) {
				System.out.println("File do not exist, connection closed!");
			} else {
				FileInputStream fileInputStream = null;
				byte[] bFile = new byte[(int) file.length()];
				fileInputStream = new FileInputStream(file);
				fileInputStream.read(bFile);
				fileInputStream.close();

				System.out.print("Enter chunk size [1024]: ");
				int chunksize = kb.nextInt();
				long filesize = file.length();
				int packets = calculatePackets(chunksize, filesize);
				StartMessage start = new StartMessage(filename, wrappedKey,
						chunksize);
				ObjectOutputStream oos = new ObjectOutputStream(os);
				ObjectInputStream ois = new ObjectInputStream(is);
				oos.writeObject(start);
				cipher = Cipher.getInstance("AES");
				Chunk chunk = null;
				byte[] chunkdata = null;
				int currentpoint = 0;
				System.out.println("Sending...");
				for (int i = 0; i < packets; i++) {
					AckMessage ack = (AckMessage) ois.readObject();
					if (ack.getSeq() == i) {
						System.out.println("Chunk [" + i + " / " + packets
								+ "]");
						if ((currentpoint + chunksize) < filesize) {
							chunkdata = new byte[chunksize];
						} else {
							chunkdata = new byte[(int) (filesize - currentpoint)];
						}
						for (int j = 0; j < chunksize
								&& ((j + currentpoint) < filesize); j++) {
							chunkdata[j] = bFile[j + currentpoint];
						}
						Checksum checksum = new CRC32();
						checksum.update(chunkdata, 0, chunkdata.length);
						long crc32 = checksum.getValue();
						cipher.init(Cipher.ENCRYPT_MODE, wrapKey);
						byte[] cipherText = cipher.doFinal(chunkdata);
						chunk = new Chunk(i, cipherText, (int) crc32);
						oos.writeObject(chunk);
						currentpoint += chunksize;
					} else {
						i = i - 1;
						oos.writeObject(chunk);
					}
				}
				System.out.println("File transfer completed");
				DisconnectMessage disconnect = new DisconnectMessage();
				oos.writeObject(disconnect);
				System.out.println("Disconnected from server");
				System.out.println("File Transfer terminated.");

			}

		}

	}

	private static void server(final String filename, String portnumber)
			throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(
				Integer.parseInt(portnumber))) {
			while (true) {
				final Socket socket = serverSocket.accept();
				Thread thread = new Thread(new Runnable() {
					public void run() {
						try {
							final String address = socket.getInetAddress()
									.getHostAddress();
							System.out
									.printf("Client connected: %s%n", address);
							InputStream is = socket.getInputStream();
							OutputStream os = socket.getOutputStream();
							PrivateKey privateKey = null;
							privateKey = loadPrivateKey(privateKey, filename);
							ObjectInputStream ois = new ObjectInputStream(is);
							ObjectOutputStream oos = new ObjectOutputStream(os);
							Object message = ois.readObject();
							StartMessage start = null;
							StopMessage stop;
							Chunk chunk;

							if (message instanceof DisconnectMessage) {
								System.out.printf("Client disconnected: %s%n",
										address);
								socket.close();
							} else {
								start = (StartMessage) message;
							}

							byte[] wrappedsessionKey = start.getEncryptedKey();

							Cipher cipher = Cipher.getInstance("RSA");
							cipher.init(Cipher.UNWRAP_MODE, privateKey);
							Key key = cipher.unwrap(wrappedsessionKey, "AES",
									Cipher.SECRET_KEY);
							int acks = 0;
							AckMessage ack = new AckMessage(acks);
							oos.writeObject(ack);

							long filesize = start.getSize();
							int chunksize = start.getChunkSize();
							int packets = calculatePackets(chunksize, filesize);
							System.out.println("Transfering..");
							System.out.println("File name: " + start.getFile());
							System.out.println("Size: " + filesize);
							System.out.println("Chunks size: " + chunksize);
							System.out.println("Total packets: " + packets);
							byte[] newfile = new byte[(int) filesize];
							cipher = Cipher.getInstance("AES");
							int currentpoint = 0;
							for (int i = 0; i < packets; i++){
								chunk = (Chunk) ois.readObject();	
								if (chunk.getSeq() == i) {
									System.out.println(i + " " + chunk.getSeq());
									cipher.init(Cipher.DECRYPT_MODE, key);
									byte[] plainText = cipher.doFinal(chunk
											.getData());
									Checksum checksum = new CRC32();
									checksum.update(plainText, 0,
											plainText.length);
									long crc32 = checksum.getValue();
									if (crc32 == (long) chunk.getCrc()) {
										for (int j = 0; j < plainText.length; j++) {
											newfile[j + currentpoint] = plainText[j];
										}
										currentpoint += plainText.length;
										ack = new AckMessage(i + 1);
										oos.writeObject(ack);
										System.out
												.println("Recieved chunk ["
														+ chunk.getSeq()
														+ " / " + packets
														+ "]");
									} else {
										ack = new AckMessage(i);
										oos.writeObject(ack);
										i--;
									}
								
								} else {
									ack = new AckMessage(i);
									oos.writeObject(ack);
									i--;
								}
							}
//							while ((message = ois.readObject()) != null) {
//								
//								if (message instanceof DisconnectMessage) {
//									System.out.printf(
//											"Client disconnected: %s%n",
//											address);
//									socket.close();
//								} else if (message instanceof StopMessage) {
//									stop = (StopMessage) message;
//									ack = new AckMessage(-1);
//									oos.writeObject(ack);
//								} else {
//									chunk = (Chunk) message;
//									System.out.println(acks + " " + chunk.getSeq());
//									if (chunk.getSeq() == acks) {
//										cipher.init(Cipher.DECRYPT_MODE, key);
//										byte[] plainText = cipher.doFinal(chunk
//												.getData());
//										Checksum checksum = new CRC32();
//										checksum.update(plainText, 0,
//												plainText.length);
//										long crc32 = checksum.getValue();
//										if (crc32 == (long) chunk.getCrc()) {
//											for (int j = 0; j < plainText.length; j++) {
//												newfile[j + currentpoint] = plainText[j];
//											}
//											currentpoint += plainText.length;
//											acks++;
//											ack = new AckMessage(acks);
//											System.out
//													.println("Recieved chunk ["
//															+ chunk.getSeq()
//															+ " / " + packets
//															+ "]");
//											if ((chunk.getSeq() == packets)) {
//												System.out
//														.print("Output path: ");
//												String newfilename = kb.next();
//												FileOutputStream fos = new FileOutputStream(
//														newfilename);
//												fos.write(newfile);
//												fos.close();
//												break;
//											}
//										} else {
//											ack = new AckMessage(acks);
//										}
//										oos.writeObject(ack);
//									} else {
//										oos.writeObject(ack);
//									}
//
//								}
//							}
						} catch (Exception e) {
							;
						}
					}
				});
				thread.start();

			}
		}
	}

	private static void makeKeys() {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096); // you can use 2048 for faster key generation
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);
		}
	}

	private static PrivateKey loadPrivateKey(PrivateKey key, String filename)
			throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(filename);
		ObjectInputStream ois = new ObjectInputStream(fis);
		key = (PrivateKey) ois.readObject();
		ois.close();
		return key;
	}

	private static PublicKey loadPublicKey(PublicKey key, String filename)
			throws IOException, ClassNotFoundException {

		FileInputStream fis = new FileInputStream(filename);
		ObjectInputStream ois = new ObjectInputStream(fis);
		key = (PublicKey) ois.readObject();
		ois.close();
		return key;
	}

	private static int calculatePackets(int chunksize, long filesize) {
		int packets = (int) filesize / chunksize;
		double a = (double) filesize / (double) chunksize;
		if (a > (double) packets) {
			packets = packets + 1;
		}
		return packets;
	}
}
