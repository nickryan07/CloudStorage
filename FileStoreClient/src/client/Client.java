package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.auth.UserRecord.CreateRequest;


public class Client {
	static String url = "http://ec2-34-238-232-189.compute-1.amazonaws.com:8080";
	
	public static void list_files() {
		try {
			System.out.println("-----------------");
		    Document doc = Jsoup.connect(url+"/FileServlet/uploads").get();
		    Elements links = doc.getElementsByTag("a");
		    for (Element link : links) {
		    	if(!link.text().equals("Up To /"))
		    		System.out.println(link.text());
		    }
		    System.out.println("-----------------");
		} catch (IOException ex) {
		    ex.printStackTrace();
		}
	}
	
	public static boolean register(String email, String pass) {
		String hex = "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
		    md.update(pass.getBytes(StandardCharsets.UTF_8));
		    byte[] digest = md.digest();
		    hex = String.format("%064x", new BigInteger(1, digest));
		    hex = hex.substring(0, Math.min(hex.length(), 16));
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		CreateRequest request = new CreateRequest()
					.setPassword(pass)
					.setEmail(email)
					.setUid(hex)
					.setEmailVerified(false);

			try {
				@SuppressWarnings("unused")
				UserRecord userRecord = FirebaseAuth.getInstance().createUserAsync(request).get();
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}
		return true;
	}
	
	public static boolean login(String email, String pass) {
		String hex = "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
		    md.update(pass.getBytes(StandardCharsets.UTF_8));
		    byte[] digest = md.digest();
		    hex = String.format("%064x", new BigInteger(1, digest));
		    hex = hex.substring(0, Math.min(hex.length(), 16));
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			UserRecord userRecord = FirebaseAuth.getInstance().getUserByEmailAsync(email).get();
			if(userRecord.getUid().equals(hex)) {
				return true;
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		System.out.println("Could not authenticate.");
		return false;
	}
	
	 static void fileProcessor(int cipherMode, String key, File inputFile, File outputFile){
		 try {
		       Key secretKey = new SecretKeySpec(key.getBytes(), "AES");
		       Cipher cipher = Cipher.getInstance("AES");
		       cipher.init(cipherMode, secretKey);

		       FileInputStream inputStream = new FileInputStream(inputFile);
		       byte[] inputBytes = new byte[(int) inputFile.length()];
		       inputStream.read(inputBytes);

		       byte[] outputBytes = cipher.doFinal(inputBytes);

		       FileOutputStream outputStream = new FileOutputStream(outputFile);
		       outputStream.write(outputBytes);

		       inputStream.close();
		       outputStream.close();

		    } catch (NoSuchPaddingException | NoSuchAlgorithmException 
	                     | InvalidKeyException | BadPaddingException
		             | IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
	            }
	     }
	
	public static void main(String[] args) throws Exception {
		// [START initialize]
	    FileInputStream serviceAccount = new FileInputStream("firebase.json");
	    FirebaseOptions options = new FirebaseOptions.Builder().setCredentials(GoogleCredentials.fromStream(serviceAccount)).build();
	    FirebaseApp.initializeApp(options);
	    // [END initialize]
        Scanner sc = new Scanner(System.in);
        boolean authenticated = false;
		while(!authenticated) {
			System.out.println("Enter one of the following commands to proceed.");
			System.out.println(" - register");
			System.out.println(" - login");
			String command = sc.nextLine();
			if(command.equalsIgnoreCase("register")) {
				System.out.print("Enter an email: ");
				String email = sc.nextLine();
				System.out.print("Enter a password: ");
				String pass = sc.nextLine();
				register(email, pass);
			} else if(command.equalsIgnoreCase("login")) {
				System.out.print("Enter an email: ");
				String email = sc.nextLine();
				System.out.print("Enter a password: ");
				String pass = sc.nextLine();
				if(login(email, pass)) {
					authenticated = true;
				}
			}
		}
        Boolean exit = false;
        String command;
		while(!exit) {
			System.out.println("Enter one of the following commands to proceed.");
			System.out.println(" - upload");
			System.out.println(" - download");
			System.out.println(" - list");
			System.out.println(" - genkey");
			command = sc.nextLine();
			if(command.equalsIgnoreCase("upload")) {
		        CloseableHttpClient httpclient = HttpClients.createDefault();
		        try {
		            HttpPost httppost = new HttpPost(url +
		                    "/FileServlet/FileServlet");
		
		            System.out.print("Enter the file to upload: ");
		            String f = sc.nextLine();
		            //-------------------Encryption--------------------
		            @SuppressWarnings("resource")
					String key = new Scanner(new File("key.dat")).useDelimiter("\\Z").next();
		            
		        	File inputFile = new File("data/"+f);
		        	File encryptedFile = new File(f);
		        	encryptedFile.createNewFile();
		        		
		        	try {
		        	     fileProcessor(Cipher.ENCRYPT_MODE,key,inputFile,encryptedFile);
		        	 } catch (Exception ex) {
		        	     System.out.println(ex.getMessage());
		                     ex.printStackTrace();
		        	 }
		         
		            //-------------------------------------------------
		            
		            FileBody bin = new FileBody(encryptedFile);
		            StringBody comment = new StringBody("A binary file", ContentType.DEFAULT_BINARY);
		
		            HttpEntity reqEntity = MultipartEntityBuilder.create()
		                    .addPart("bin", bin)
		                    .addPart("comment", comment)
		                    .build();
		
		
		            httppost.setEntity(reqEntity);
		
		            System.out.println("executing request " + httppost.getRequestLine());
		            CloseableHttpResponse response = httpclient.execute(httppost);
		            encryptedFile.delete();
		            try {
		                System.out.println("----------------------------------------");
		                System.out.println(response.getStatusLine());
		                HttpEntity resEntity = response.getEntity();
		                if (resEntity != null) {
		                    System.out.println("Response content length: " + resEntity.getContentLength());
		                }
		                EntityUtils.consume(resEntity);
		            } finally {
		                response.close();
		            }
		        } finally {
		            httpclient.close();
		        }
			} else if(command.equalsIgnoreCase("download")) {
				Boolean stop = false;
				ArrayList<String> a = new ArrayList<String>();
				System.out.print("Enter the files to download press q to stop: ");
				while(!stop) {
					String f = sc.nextLine();
					if(!f.equalsIgnoreCase("q"))
						a.add(f);
					else
						stop = true;
				}
				while(!a.isEmpty()) {
					String f = a.get(0);
					a.remove(0);
			        @SuppressWarnings("resource")
					String key = new Scanner(new File("key.dat")).useDelimiter("\\Z").next();
			        
		            File myFile = new File(f);
		            URIBuilder builder = new URIBuilder();
		            builder.setScheme("http").setHost("ec2-34-238-232-189.compute-1.amazonaws.com").setPort(8080).setPath("/FileServlet/FileServlet")
		                .setParameter("fileName", f);
		            URI uri = builder.build();
		            CloseableHttpClient client = HttpClients.createDefault();
		            try (CloseableHttpResponse response = client.execute(new HttpGet(uri))) {
		                HttpEntity entity = response.getEntity();
		                if (entity != null) {
		                    try (FileOutputStream outstream = new FileOutputStream(myFile)) {
		                        entity.writeTo(outstream);
		                    }
		                }
		            }
		            
		        	File encryptedFile = new File(f);
		        	encryptedFile.createNewFile();
		        	File decryptedFile = new File(f+"dec");
		        	decryptedFile.createNewFile();
		        	
		        	try {
		        	     fileProcessor(Cipher.DECRYPT_MODE,key,encryptedFile,decryptedFile);
		        	     encryptedFile.delete();
		        	     decryptedFile.renameTo(encryptedFile);
		        	 } catch (Exception ex) {
		        	     System.out.println(ex.getMessage());
		                 ex.printStackTrace();
		        	 }
				}
			} else if(command.equalsIgnoreCase("list")) {
				list_files();
			} else if(command.equalsIgnoreCase("genkey")) {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
			    System.out.println("Enter a password to use as your encryption key: ");
			    String k = sc.nextLine();
			    md.update(k.getBytes(StandardCharsets.UTF_8));
			    byte[] digest = md.digest();
			    String hex = String.format("%064x", new BigInteger(1, digest));
			    hex = hex.substring(0, Math.min(hex.length(), 16));
			    System.out.println(hex);
				File key_file = new File("key.dat");
				final PrintStream fileout = new PrintStream(key_file);
				fileout.write(hex.getBytes());
				fileout.close();
			} else if(command.equals("q")) {
				exit = true;
			}
		}
		sc.close();
    }
}