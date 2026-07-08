//Date:         07/01/2026
//Authors:      Murphy Jacob, Gauri Kaushik, Shehtaz Mahboob, Colton Moore
//Instructor:   Diane Rabah

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <string>
#include <unordered_map>
#include <unordered_set>

extern "C" {

// ---------------------------------------------------------------------------
// Random bytes (CSPRNG)
// ---------------------------------------------------------------------------
int vc_random_bytes(uint8_t* out, int n) {
    return RAND_bytes(out, n) == 1 ? 0 : -1;
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 key derivation
// ---------------------------------------------------------------------------
int vc_derive_key(const char* password, int pw_len,
                  const uint8_t* salt, int salt_len,
                  int iterations, uint8_t* out_key32) {
    return PKCS5_PBKDF2_HMAC(password, pw_len, salt, salt_len,
                             iterations, EVP_sha256(), 32, out_key32) == 1 ? 0 : -1;
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt.
// Output layout: [12-byte IV][ciphertext][16-byte tag]
// Returns total output length, or -1 on failure.
// ---------------------------------------------------------------------------
int vc_encrypt(const uint8_t* key32,
               const uint8_t* plaintext, int pt_len,
               uint8_t* out, int out_cap) {
    if (out_cap < 12 + pt_len + 16) return -1;

    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = -1, len = 0, ct_len = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32, iv) != 1) break;
        if (EVP_EncryptUpdate(ctx, out + 12, &len, plaintext, pt_len) != 1) break;
        ct_len = len;
        if (EVP_EncryptFinal_ex(ctx, out + 12 + ct_len, &len) != 1) break;
        ct_len += len;
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;
        memcpy(out, iv, 12);
        memcpy(out + 12 + ct_len, tag, 16);
        ok = 12 + ct_len + 16;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ---------------------------------------------------------------------------
// AES-256-GCM decrypt. Input layout must match vc_encrypt output.
// Returns plaintext length, or -1 on failure / authentication error.
// ---------------------------------------------------------------------------
int vc_decrypt(const uint8_t* key32,
               const uint8_t* blob, int blob_len,
               uint8_t* out, int out_cap) {
    if (blob_len < 12 + 16) return -1;
    int ct_len = blob_len - 12 - 16;
    if (out_cap < ct_len) return -1;

    const uint8_t* iv  = blob;
    const uint8_t* ct  = blob + 12;
    uint8_t tag[16];
    memcpy(tag, blob + 12 + ct_len, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = -1, len = 0, pt_len = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32, iv) != 1) break;
        if (EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) != 1) break;
        pt_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, out + pt_len, &len) != 1) break;  // tag check
        pt_len += len;
        ok = pt_len;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ---------------------------------------------------------------------------
// SHA-1 hex digest (uppercase) — used only for the HaveIBeenPwned
// k-anonymity protocol. out must hold 41 bytes (40 hex + NUL).
// ---------------------------------------------------------------------------
int vc_sha1_hex(const uint8_t* data, int len, char* out41) {
    uint8_t digest[SHA_DIGEST_LENGTH];
    if (!SHA1(data, (size_t)len, digest)) return -1;
    static const char* hex = "0123456789ABCDEF";
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        out41[i * 2]     = hex[digest[i] >> 4];
        out41[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out41[40] = '\0';
    return 0;
}

// ---------------------------------------------------------------------------
// Password analysis
// ---------------------------------------------------------------------------

// Charset-pool entropy in bits: length * log2(pool size)
double vc_entropy_bits(const char* password) {
    if (!password) return 0.0;
    size_t n = strlen(password);
    if (n == 0) return 0.0;

    bool lower = false, upper = false, digit = false, symbol = false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)password[i];
        if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= 'A' && c <= 'Z') upper = true;
        else if (c >= '0' && c <= '9') digit = true;
        else symbol = true;
    }
    int pool = 0;
    if (lower)  pool += 26;
    if (upper)  pool += 26;
    if (digit)  pool += 10;
    if (symbol) pool += 33;   // printable ASCII symbols
    if (pool == 0) return 0.0;
    return (double)n * std::log2((double)pool);
}

// Fraction of the password consumed by immediate character repeats
// ("aaa", "111") and adjacent sequences ("abc", "321").  0.0 = none.
double vc_repetition_ratio(const char* password) {
    if (!password) return 0.0;
    size_t n = strlen(password);
    if (n < 2) return 0.0;
    int weak_pairs = 0;
    for (size_t i = 1; i < n; ++i) {
        int diff = (int)password[i] - (int)password[i - 1];
        if (diff == 0 || diff == 1 || diff == -1) ++weak_pairs;
    }
    return (double)weak_pairs / (double)(n - 1);
}

// Composite strength score 0..100.
// Blends charset entropy with penalties for repetition/sequences and for
// very low character-class diversity.
int vc_strength_score(const char* password) {
    if (!password || !*password) return 0;
    double bits = vc_entropy_bits(password);
    double base = (bits / 80.0) * 100.0;             // 80 bits -> 100
    if (base > 100.0) base = 100.0;

    double rep = vc_repetition_ratio(password);      // 0..1
    base *= (1.0 - 0.6 * rep);                       // up to -60% penalty

    // diversity penalty: single character class caps the score
    size_t n = strlen(password);
    bool classes[4] = {false, false, false, false};
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)password[i];
        if (c >= 'a' && c <= 'z') classes[0] = true;
        else if (c >= 'A' && c <= 'Z') classes[1] = true;
        else if (c >= '0' && c <= '9') classes[2] = true;
        else classes[3] = true;
    }
    int nclasses = classes[0] + classes[1] + classes[2] + classes[3];
    if (nclasses == 1 && base > 55.0) base = 55.0;
    if (nclasses == 2 && base > 80.0) base = 80.0;

    int score = (int)std::lround(base);
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return score;
}

// ---------------------------------------------------------------------------
// Policy-aware password generation (rejection-sampled, unbiased).
//   length          desired length (caller enforces site max-length policy)
//   use_upper/digits/symbols   class toggles
//   allowed_symbols nullable; when set, only these symbols are used
//                   (supports site policies that permit specific specials)
// Guarantees at least one char from each enabled class when length allows.
// Returns 0 on success.
// ---------------------------------------------------------------------------
int vc_generate_password(int length, int use_upper, int use_digits,
                         int use_symbols, const char* allowed_symbols,
                         char* out, int out_cap) {
    if (length < 4 || length >= out_cap) return -1;

    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    std::string symbols = "!@#$%^&*()-_=+[]{};:,.?";
    if (allowed_symbols && *allowed_symbols) symbols = allowed_symbols;

    std::string pool = lower;
    if (use_upper)   pool += upper;
    if (use_digits)  pool += digits;
    if (use_symbols) pool += symbols;

    auto pick = [](const std::string& set, char& c) -> bool {
        // rejection sampling to avoid modulo bias
        const unsigned limit = 256 - (256 % (unsigned)set.size());
        uint8_t b;
        for (int tries = 0; tries < 512; ++tries) {
            if (RAND_bytes(&b, 1) != 1) return false;
            if ((unsigned)b < limit) { c = set[b % set.size()]; return true; }
        }
        return false;
    };

    for (int attempt = 0; attempt < 64; ++attempt) {
        bool ok = true;
        for (int i = 0; i < length; ++i)
            if (!pick(pool, out[i])) { ok = false; break; }
        if (!ok) return -1;
        out[length] = '\0';

        // verify class coverage
        bool has_l = false, has_u = !use_upper, has_d = !use_digits, has_s = !use_symbols;
        for (int i = 0; i < length; ++i) {
            char c = out[i];
            if (lower.find(c)   != std::string::npos) has_l = true;
            if (upper.find(c)   != std::string::npos) has_u = true;
            if (digits.find(c)  != std::string::npos) has_d = true;
            if (symbols.find(c) != std::string::npos) has_s = true;
        }
        int enabled = 1 + (use_upper?1:0) + (use_digits?1:0) + (use_symbols?1:0);
        if (length < enabled) return -1;     // policy impossible
        if (has_l && has_u && has_d && has_s) return 0;
        // else resample
    }
    return -1;
}

} // extern "C"
