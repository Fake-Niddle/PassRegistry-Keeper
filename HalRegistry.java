import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

//Created by Stefan Dragisic 

//Using parts for code from unknown authors
//http://stackoverflow.com/questions/62289/read-write-to-windows-registry-using-java?rq=1
//22.5.2015

public class HalRegistry {
	public static final int HKEY_CURRENT_USER = 0x80000001;
	public static final int HKEY_LOCAL_MACHINE = 0x80000002;
	public static final int REG_SUCCESS = 0;
	public static final int REG_NOTFOUND = 2;
	public static final int REG_ACCESSDENIED = 5;

	private static final int KEY_ALL_ACCESS = 0xf003f;
	private static final int KEY_READ = 0x20019;
	private static Preferences userRoot = Preferences.userRoot();
	private static Preferences systemRoot = Preferences.systemRoot();
	private static Class<? extends Preferences> userClass = userRoot.getClass();
	private static Method regOpenKey = null;
	private static Method regCloseKey = null;
	private static Method regQueryValueEx = null;
	private static Method regEnumValue = null;
	private static Method regQueryInfoKey = null;
	private static Method regEnumKeyEx = null;
	private static Method regCreateKeyEx = null;
	private static Method regSetValueEx = null;
	private static Method regDeleteKey = null;
	private static Method regDeleteValue = null;
	
	public static class AESEncryptor {
		private static String algorithm = "AES";
		static String mykey = "";

		// Performs Encryption
		public static String encrypt(String plainText, String encryptkey)
				throws Exception {
			mykey = encryptkey;

			Key key = generateKey();
			Cipher chiper = Cipher.getInstance(algorithm);
			chiper.init(Cipher.ENCRYPT_MODE, key);
			byte[] encVal = chiper.doFinal(plainText.getBytes());
			String encryptedValue = new BASE64Encoder().encode(encVal);
			return encryptedValue;
		}

		// Performs decryption
		public static String decrypt(String encryptedText, String encryptkey)
				throws Exception {
			mykey = encryptkey;

			// generate key
			Key key = generateKey();
			Cipher chiper = Cipher.getInstance(algorithm);
			chiper.init(Cipher.DECRYPT_MODE, key);
			byte[] decordedValue = new BASE64Decoder()
					.decodeBuffer(encryptedText);
			byte[] decValue = chiper.doFinal(decordedValue);
			String decryptedValue = new String(decValue);
			return decryptedValue;
		}

		// generateKey() is used to generate a secret key for AES algorithm
		private static Key generateKey() throws Exception {
			Key key = new SecretKeySpec(mykey.getBytes("UTF-8"), algorithm);
			return key;
		}



	}

	static {
		try {
			regOpenKey = userClass.getDeclaredMethod("WindowsRegOpenKey",
					new Class[] { int.class, byte[].class, int.class });
			regOpenKey.setAccessible(true);
			regCloseKey = userClass.getDeclaredMethod("WindowsRegCloseKey",
					new Class[] { int.class });
			regCloseKey.setAccessible(true);
			regQueryValueEx = userClass.getDeclaredMethod(
					"WindowsRegQueryValueEx", new Class[] { int.class,
							byte[].class });
			regQueryValueEx.setAccessible(true);
			regEnumValue = userClass.getDeclaredMethod("WindowsRegEnumValue",
					new Class[] { int.class, int.class, int.class });
			regEnumValue.setAccessible(true);
			regQueryInfoKey = userClass.getDeclaredMethod(
					"WindowsRegQueryInfoKey1", new Class[] { int.class });
			regQueryInfoKey.setAccessible(true);
			regEnumKeyEx = userClass.getDeclaredMethod("WindowsRegEnumKeyEx",
					new Class[] { int.class, int.class, int.class });
			regEnumKeyEx.setAccessible(true);
			regCreateKeyEx = userClass.getDeclaredMethod(
					"WindowsRegCreateKeyEx", new Class[] { int.class,
							byte[].class });
			regCreateKeyEx.setAccessible(true);
			regSetValueEx = userClass.getDeclaredMethod("WindowsRegSetValueEx",
					new Class[] { int.class, byte[].class, byte[].class });
			regSetValueEx.setAccessible(true);
			regDeleteValue = userClass.getDeclaredMethod(
					"WindowsRegDeleteValue", new Class[] { int.class,
							byte[].class });
			regDeleteValue.setAccessible(true);
			regDeleteKey = userClass.getDeclaredMethod("WindowsRegDeleteKey",
					new Class[] { int.class, byte[].class });
			regDeleteKey.setAccessible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private HalRegistry() {
	}

	/**
	 * Read a value from key and value name
	 * 
	 * @param hkey
	 *            HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
	 * @param key
	 * @param valueName
	 * @return the value
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static String readRegistry(int hkey, String key, String valueName)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		if (hkey == HKEY_LOCAL_MACHINE) {
			return readString(systemRoot, hkey, key, valueName);
		} else if (hkey == HKEY_CURRENT_USER) {
			return readString(userRoot, hkey, key, valueName);
		} else {
			throw new IllegalArgumentException("hkey=" + hkey);
		}
	}

	/**
	 * Read value(s) and value name(s) form given key
	 * 
	 * @param hkey
	 *            HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
	 * @param key
	 * @return the value name(s) plus the value(s)
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static Map<String, String> readStringValues(int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		if (hkey == HKEY_LOCAL_MACHINE) {
			return readStringValues(systemRoot, hkey, key);
		} else if (hkey == HKEY_CURRENT_USER) {
			return readStringValues(userRoot, hkey, key);
		} else {
			throw new IllegalArgumentException("hkey=" + hkey);
		}
	}

	/**
	 * Read the value name(s) from a given key
	 * 
	 * @param hkey
	 *            HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
	 * @param key
	 * @return the value name(s)
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static List<String> readStringSubKeys(int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		if (hkey == HKEY_LOCAL_MACHINE) {
			return readStringSubKeys(systemRoot, hkey, key);
		} else if (hkey == HKEY_CURRENT_USER) {
			return readStringSubKeys(userRoot, hkey, key);
		} else {
			throw new IllegalArgumentException("hkey=" + hkey);
		}
	}

	/**
	 * Create a key
	 * 
	 * @param hkey
	 *            HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
	 * @param key
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static void createKey(int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int[] ret;
		if (hkey == HKEY_LOCAL_MACHINE) {
			ret = createKey(systemRoot, hkey, key);
			regCloseKey
					.invoke(systemRoot, new Object[] { new Integer(ret[0]) });
		} else if (hkey == HKEY_CURRENT_USER) {
			ret = createKey(userRoot, hkey, key);
			regCloseKey.invoke(userRoot, new Object[] { new Integer(ret[0]) });
		} else {
			throw new IllegalArgumentException("hkey=" + hkey);
		}
		if (ret[1] != REG_SUCCESS) {
			throw new IllegalArgumentException("rc=" + ret[1] + "  key=" + key);
		}
	}

	/**
	 * Write a value in a given key/value name
	 * 
	 * @param hkey
	 * @param key
	 * @param valueName
	 * @param value
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static void writeToRegistry(int hkey, String key, String valueName,
			String value) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		if (hkey == HKEY_LOCAL_MACHINE) {
			writeStringValue(systemRoot, hkey, key, valueName, value);
		} else if (hkey == HKEY_CURRENT_USER) {
			writeStringValue(userRoot, hkey, key, valueName, value);
		} else {
			throw new IllegalArgumentException("hkey=" + hkey);
		}
	}

	/**
	 * Delete a given key
	 * 
	 * @param hkey
	 * @param key
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static void deleteKey(int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int rc = -1;
		if (hkey == HKEY_LOCAL_MACHINE) {
			rc = deleteKey(systemRoot, hkey, key);
		} else if (hkey == HKEY_CURRENT_USER) {
			rc = deleteKey(userRoot, hkey, key);
		}
		if (rc != REG_SUCCESS) {
			throw new IllegalArgumentException("rc=" + rc + "  key=" + key);
		}
	}

	/**
	 * delete a value from a given key/value name
	 * 
	 * @param hkey
	 * @param key
	 * @param value
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static void deleteValue(int hkey, String key, String value)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int rc = -1;
		if (hkey == HKEY_LOCAL_MACHINE) {
			rc = deleteValue(systemRoot, hkey, key, value);
		} else if (hkey == HKEY_CURRENT_USER) {
			rc = deleteValue(userRoot, hkey, key, value);
		}
		if (rc != REG_SUCCESS) {
			throw new IllegalArgumentException("rc=" + rc + "  key=" + key
					+ "  value=" + value);
		}
	}

	// =====================

	private static int deleteValue(Preferences root, int hkey, String key,
			String value) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key), new Integer(KEY_ALL_ACCESS) });
		if (handles[1] != REG_SUCCESS) {
			return handles[1]; 
		}
		int rc = ((Integer) regDeleteValue.invoke(root, new Object[] {
				new Integer(handles[0]), toCstr(value) })).intValue();
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return rc;
	}

	private static int deleteKey(Preferences root, int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int rc = ((Integer) regDeleteKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key) })).intValue();
		return rc; 
	}

	private static String readString(Preferences root, int hkey, String key,
			String value) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key), new Integer(KEY_READ) });
		if (handles[1] != REG_SUCCESS) {
			return null;
		}
		byte[] valb = (byte[]) regQueryValueEx.invoke(root, new Object[] {
				new Integer(handles[0]), toCstr(value) });
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return (valb != null ? new String(valb).trim() : null);
	}

	private static Map<String, String> readStringValues(Preferences root,
			int hkey, String key) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		HashMap<String, String> results = new HashMap<String, String>();
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key), new Integer(KEY_READ) });
		if (handles[1] != REG_SUCCESS) {
			return null;
		}
		int[] info = (int[]) regQueryInfoKey.invoke(root,
				new Object[] { new Integer(handles[0]) });

		int count = info[0]; 
		int maxlen = info[3]; 
		for (int index = 0; index < count; index++) {
			byte[] name = (byte[]) regEnumValue.invoke(root, new Object[] {
					new Integer(handles[0]), new Integer(index),
					new Integer(maxlen + 1) });
			String value = readRegistry(hkey, key, new String(name));
			results.put(new String(name).trim(), value);
		}
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return results;
	}

	private static List<String> readStringSubKeys(Preferences root, int hkey,
			String key) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		List<String> results = new ArrayList<String>();
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key), new Integer(KEY_READ) });
		if (handles[1] != REG_SUCCESS) {
			return null;
		}
		int[] info = (int[]) regQueryInfoKey.invoke(root,
				new Object[] { new Integer(handles[0]) });

		int count = info[0]; 
								
								
		int maxlen = info[3]; 
		for (int index = 0; index < count; index++) {
			byte[] name = (byte[]) regEnumKeyEx.invoke(root, new Object[] {
					new Integer(handles[0]), new Integer(index),
					new Integer(maxlen + 1) });
			results.add(new String(name).trim());
		}
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return results;
	}

	private static int[] createKey(Preferences root, int hkey, String key)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		return (int[]) regCreateKeyEx.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key) });
	}

	private static void writeStringValue(Preferences root, int hkey,
			String key, String valueName, String value)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key), new Integer(KEY_ALL_ACCESS) });

		regSetValueEx.invoke(root, new Object[] { new Integer(handles[0]),
				toCstr(valueName), toCstr(value) });
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
	}

	// utility
	private static byte[] toCstr(String str) {
		byte[] result = new byte[str.length() + 1];

		for (int i = 0; i < str.length(); i++) {
			result[i] = (byte) str.charAt(i);
		}
		result[str.length()] = 0;
		return result;
	}

	
	public static String readEncryptedRegistry(int hkey, String key,
			String valueName, String encryptKey) throws Exception {

		return AESEncryptor.decrypt(readRegistry(hkey, key, valueName),
				encryptKey);
	}

	public static void writeEncryptedToRegistry(int hkey, String key,
			String valueName, String value, String encryptKey) throws Exception {

		writeToRegistry(hkey, key, valueName,
				AESEncryptor.encrypt(value, encryptKey));

	}
	
	



	public static void main(String[] args) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
		
		//Example encryption key
		//16 chars = 128bit AES

		String encryptionKey = "M,3S[)sGuq{ji-sA"; 
		String value = null;
		
	
			try {
				//Example creating new key
				HalRegistry.createKey(HKEY_CURRENT_USER, "MyNewKey");


				HalRegistry.writeEncryptedToRegistry(HKEY_CURRENT_USER, "MyNewKey", "db_password",
						"mysecret_password",encryptionKey);
		
				
		
				//Example reading reg key
				value = HalRegistry.readEncryptedRegistry(HalRegistry.HKEY_CURRENT_USER, // HKEY
					"MyNewKey", // Key
					"db_password",encryptionKey);

			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // ValueName
		System.out.println("Win reg = " + value);
	}

}