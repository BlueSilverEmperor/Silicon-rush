/**
 * AXION Cryptographic Engine (WebCrypto API)
 * Fully compatible with AXION Python desktop encryption (medium.py / #merge org.py)
 * 
 * Cryptographic Specifications:
 * - Cipher: AES-256-CBC
 * - Key Derivation: PBKDF2 with HMAC-SHA256
 * - Salt: 16 bytes (cryptographically secure random)
 * - IV: 16 bytes (cryptographically secure random)
 * - Iterations: 100,000
 * - Padding: PKCS#7 (handled natively by WebCrypto AES-CBC)
 * - Binary Layout: [ Salt (16B) | IV (16B) | Ciphertext (variable) ]
 */

const AxionCrypto = (() => {
  const SALT_SIZE = 16;
  const IV_SIZE = 16;
  const KEY_SIZE = 32; // 256 bits
  const DEFAULT_ITERATIONS = 100000;
  const MAGIC_HEADER = null; // Standard format: raw [salt][iv][ciphertext]

  /**
   * Derive an AES-CBC 256-bit key from password and salt using PBKDF2-SHA256
   */
  async function deriveKey(password, salt, iterations = DEFAULT_ITERATIONS) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256',
      },
      baseKey,
      {
        name: 'AES-CBC',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt file or buffer
   * @param {ArrayBuffer|Uint8Array} plaintextData 
   * @param {string} password 
   * @param {number} iterations 
   * @returns {Promise<Uint8Array>} Encrypted .docenc binary payload
   */
  async function encrypt(plaintextData, password, iterations = DEFAULT_ITERATIONS) {
    if (!password || password.length < 4) {
      throw new Error('Password must be at least 4 characters.');
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));

    const key = await deriveKey(password, salt, iterations);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: iv,
      },
      key,
      plaintextData
    );

    const ciphertext = new Uint8Array(ciphertextBuffer);

    // Combine: [salt (16)] + [iv (16)] + [ciphertext]
    const totalLength = salt.length + iv.length + ciphertext.length;
    const combined = new Uint8Array(totalLength);
    combined.set(salt, 0);
    combined.set(iv, SALT_SIZE);
    combined.set(ciphertext, SALT_SIZE + IV_SIZE);

    return combined;
  }

  /**
   * Decrypt .docenc binary payload
   * @param {ArrayBuffer|Uint8Array} encryptedData 
   * @param {string} password 
   * @param {number} iterations 
   * @returns {Promise<Uint8Array>} Decrypted plaintext data
   */
  async function decrypt(encryptedData, password, iterations = DEFAULT_ITERATIONS) {
    if (!password || password.length < 4) {
      throw new Error('Password must be at least 4 characters.');
    }

    const data = encryptedData instanceof Uint8Array ? encryptedData : new Uint8Array(encryptedData);

    if (data.length < SALT_SIZE + IV_SIZE + 1) {
      throw new Error('File is too short or not a valid .docenc file.');
    }

    const salt = data.subarray(0, SALT_SIZE);
    const iv = data.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
    const ciphertext = data.subarray(SALT_SIZE + IV_SIZE);

    const key = await deriveKey(password, salt, iterations);

    try {
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-CBC',
          iv: iv,
        },
        key,
        ciphertext
      );
      return new Uint8Array(plaintextBuffer);
    } catch (err) {
      throw new Error('Decryption failed: Incorrect password or corrupted .docenc file.');
    }
  }

  /**
   * Encrypt a text string directly into Base64 or Uint8Array
   */
  async function encryptText(text, password, iterations = DEFAULT_ITERATIONS) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    const encrypted = await encrypt(bytes, password, iterations);
    return bytesToBase64(encrypted);
  }

  /**
   * Decrypt a Base64 string directly back to UTF-8 text
   */
  async function decryptText(base64Str, password, iterations = DEFAULT_ITERATIONS) {
    const encryptedBytes = base64ToBytes(base64Str.trim());
    const decryptedBytes = await decrypt(encryptedBytes, password, iterations);
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBytes);
  }

  function bytesToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  return {
    encrypt,
    decrypt,
    encryptText,
    decryptText,
    bytesToBase64,
    base64ToBytes,
    SALT_SIZE,
    IV_SIZE,
    DEFAULT_ITERATIONS,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AxionCrypto;
}
