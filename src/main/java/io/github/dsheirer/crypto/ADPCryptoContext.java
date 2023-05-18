
package io.github.dsheirer.crypto;

import jmbe.iface.ICryptoContext;

public class ADPCryptoContext implements ICryptoContext {

    private int offset;
    private int[] key;
    private int[] keystream;
    private int[] state;

    public ADPCryptoContext(int[] key, int[] iv) {
        this.key = new int[13];
        this.keystream = new int[469];
        this.state = new int[256];

        // copy at most 5 bytes from the provided key
        for (int i = 0; i < Math.min(key.length, 5); i++) {
            this.key[i] = key[i];
        }
        // copy at most 8 bytes from the provided IV
        for (int i = 0; i < Math.min(iv.length, 8); i++) {
            this.key[i + 5] = iv[i];
        }

        this.init();
    }

    private void init() {
        int i, j = 0;

        // initialize s-box
        for (i = 0; i < 256; i++) {
            this.state[i] = i;
        }

        // perform initial mixing on s-box
        for (i = 0; i < 256; i++) {
            j = (j + this.state[i] + this.key[i % this.key.length]) & 0xff;

            // swap
            int tmp = this.state[i];
            this.state[i] = this.state[j];
            this.state[j] = tmp;
        }

        // generate keystream
        i = j = 0;
        for (int count = 0; count < this.keystream.length; count++) {
            i = (i + 1) & 0xff;
            j = (j + this.state[i]) & 0xff;

            // swap
            int tmp = this.state[i];
            this.state[i] = this.state[j];
            this.state[j] = tmp;

            int idx = (this.state[i] + this.state[j]) & 0xff;
            this.keystream[count] = this.state[idx];
        }
    }

    @Override
    public void process(int[] cipherText) {
        for (int i = 0; i < cipherText.length; i++) {
            cipherText[i] ^= this.keystream[this.offset + i];
        }

        // XXX P25 phase 2 hack
        cipherText[6] &= 0x80;
    }

    @Override
    public void setOffset(int offset) {
        this.offset = offset;
    }
}
