
'use strict'
/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/


const MAX_SKIP = 256;

async function KDF_RK(rk, dh_out){
  return await HKDF(rk, dh_out, "arbitaryConstant")
}

async function KDF_CK(ck) {
  const exportToArrayBuffer = false;
  const salt = await HMACtoHMACKey(ck, "salt");
  const [mkSalt, chainKeySalt] = await HKDF(salt, salt, "randomString");
  const new_chainKey = await HMACtoHMACKey(chainKeySalt, "randomString");
  const message_key = await HMACtoAESKey(mkSalt, "randomString", exportToArrayBuffer);
  const mk_Buf = await HMACtoAESKey(mkSalt, "randomString", !exportToArrayBuffer);
  return [new_chainKey, message_key, mk_Buf];
}


async function GENERATE_DH()
{
  return await generateEG()
}

async function DH(dh_pair, dh_pub)
{
  return computeDH(dh_pair.sec, dh_pub);
}


async function DHRatchet(state, header) {
  state.PN = state.Ns                         
  state.Ns = 0
  state.Nr = 0
  state.DHr = header.dh
  [state.rk, state.ckr] = await KDF_RK(state.RK, DH(state.DHs.sec, state.DHr))
  state.DHs = GENERATE_DH()
  [state.rk, state.ckr] = await KDF_RK(state.RK, DH(state.DHs.sec, state.DHr))
}


class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey

    this.conns = {} // data for each active state
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG();
    const kp_Object = await generateEG()
    this.EGKeyPair = kp_Object
    const certificate = {"username": username,"pub" : kp_Object.pub,};
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const verification = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
    if (!verification) {
      throw ("Invalid Cerificate");
    }
    this.certs[certificate.username] = certificate;
  }
  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async TrySkippedMessageKeys(name, state, header, ciphertext) {
    if ((header.dh, header.N) in state.MKSKIPPED) {
      const mk = state.MKSKIPPED[(header.dh, header.N)];
      delete state.MKSKIPPED[(header.dh, header.N)];
      try {
        const plaintextBuffer = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
        const plaintext = byteArrayToString(plaintextBuffer);
        return plaintext;
      } catch (error) {
        throw new Error("Decryption failed: " + error.message);
      } 
    }
    else{
      return null;
    }
    
  }
  
  async SkipMessageKeys(state, until) {
    if (state.Nr + MAX_SKIP < until) {
      throw Exception
    }
    if (state.CKr !== null) {
      while (state.Nr < until) {
        const [ckr, mk] = await KDF_CK(state.CKr);
        state.CKr = ckr;
        state.MKSKIPPED[(state.DHr, state.Nr)] = mk;
        state.Nr += 1;
      }
    }
    return state;
  }

  async createConnection(name) {
    if (!(name in this.conns)) { 
      let certif = this.certs[name]
      const dhs = await generateEG();
      const RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      const dhhs = await computeDH(dhs.sec, certif.pub);
      const [rk, cks] = await KDF_RK(RootKey, dhhs);
  
      this.conns[name] = {
        DHkeyPair: this.EGKeyPair,
        RK: rk,
        DHs: dhs,
        DHr: certif.pub,
        CKs: cks,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        isSender : false,
        MKSKIPPED: {}, 
      };
    }
  
    const state = this.conns[name];
    if (!state.CKs) {
      let certif = this.certs[name]
      const RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      const dhs = await generateEG();
      const dHS = await computeDH(dhs.sec, certif.pub);
      const [rk, cks] = await KDF_RK(RootKey, dHS);
      state.DHs = dhs
      state.CKs = cks
    }
  }

  async sendMessage(name, plaintext) {
    await this.createConnection(name);
    const state = this.conns[name];
    const [CKs, mk, mkBuf] = await KDF_CK(state.CKs);
    state.CKs = CKs;

    const salt = genRandomSalt();
    const ivGov = genRandomSalt();
    const dhGov = await generateEG();
    const kGov = await computeDH(dhGov.sec, this.govPublicKey);
    const aesGov = await HMACtoAESKey(kGov, govEncryptionDataStr, false);
    const cGov = await encryptWithGCM(aesGov, mkBuf, ivGov)

    const header = {
      DH: state.DHs.pub,
      N: state.Ns,
      receiverIV: salt,
      vGov: dhGov.pub,
      cGov: cGov,
      ivGov: ivGov,
    }
    state.Ns = state.Ns + 1
    
    const ciphertext = await encryptWithGCM(mk, plaintext, salt, JSON.stringify(header));
    return [header, ciphertext]
  }
  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */

  async receiveMessage (name, [header, ciphertext]) {
    //Receive an encrypted message from the user specified by name
    if (!(name in this.conns)) { 
      let certif = this.certs[name]
      let RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      let dhSS = await computeDH(this.EGKeyPair.sec, header.DH);
      let [rk, ckr] = await KDF_RK(RootKey, dhSS);

      this.conns[name] = {
        DHr: header.DH,
        RK: RootKey,
        CKr: ckr,
        Nr: 0,
        MKSKIPPED: {}, 
      };
    }
    let state = this.conns[name];
    if (!state.CKr) {
      let certif = this.certs[name]
      let RootKey = await computeDH(this.EGKeyPair.sec, certif.pub);
      let dhhs = await computeDH(this.EGKeyPair.sec, header.DH);
      let [rk, ckr] = await KDF_RK(RootKey, dhhs);
      state.CKr = ckr;
      state.DHr = header.DH;
    }

    let plaintext = await this.TrySkippedMessageKeys(name, state, header, ciphertext);
    if (plaintext !== null) return plaintext;
    state = await this.SkipMessageKeys(state, header.N);
    let [CKr, mk] = await KDF_CK(state.CKr);
    state.CKr = CKr;
    state.Nr = state.Nr + 1;

    try {
      let plaintextBuffer = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
      let plaintext = byteArrayToString(plaintextBuffer);
      this.conns[name] = Object.assign({}, state);
      return plaintext;
    } catch (error) {
      throw new Error("Failed: " + error.message);
    } 
  }
};

module.exports = {
  MessengerClient
}