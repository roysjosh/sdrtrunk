/*
 *
 *  * ******************************************************************************
 *  * Copyright (C) 2014-2019 Dennis Sheirer
 *  *
 *  * This program is free software: you can redistribute it and/or modify
 *  * it under the terms of the GNU General Public License as published by
 *  * the Free Software Foundation, either version 3 of the License, or
 *  * (at your option) any later version.
 *  *
 *  * This program is distributed in the hope that it will be useful,
 *  * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  * GNU General Public License for more details.
 *  *
 *  * You should have received a copy of the GNU General Public License
 *  * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *  * *****************************************************************************
 *
 *
 */

package io.github.dsheirer.module.decode.p25.phase2.timeslot;

import io.github.dsheirer.bits.BinaryMessage;
import io.github.dsheirer.bits.CorrectedBinaryMessage;
import io.github.dsheirer.edac.ReedSolomon_63_35_29_P25;
import io.github.dsheirer.module.decode.p25.phase2.enumeration.DataUnitID;
import io.github.dsheirer.module.decode.p25.phase2.enumeration.Voice4VOffset;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.MacMessage;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.MacMessageFactory;
import io.github.dsheirer.module.decode.p25.phase2.message.mac.UnknownMacMessage;

import java.util.List;

/**
 * Slow Associated Control CHannel (SACCH) timeslot carrying an I-OEMI message
 */
public class SacchTimeslot extends AbstractSignalingTimeslot
{
    private static final int[] INFO_1 = {2, 3, 4, 5, 6, 7};
    private static final int[] INFO_2 = {8, 9, 10, 11, 12, 13};
    private static final int[] INFO_3 = {14, 15, 16, 17, 18, 19};
    private static final int[] INFO_4 = {20, 21, 22, 23, 24, 25};
    private static final int[] INFO_5 = {26, 27, 28, 29, 30, 31};
    private static final int[] INFO_6 = {32, 33, 34, 35, 36, 37};
    private static final int[] INFO_7 = {38, 39, 40, 41, 42, 43};
    private static final int[] INFO_8 = {44, 45, 46, 47, 48, 49};
    private static final int[] INFO_9 = {50, 51, 52, 53, 54, 55};
    private static final int[] INFO_10 = {56, 57, 58, 59, 60, 61};
    private static final int[] INFO_11 = {62, 63, 64, 65, 66, 67};
    private static final int[] INFO_12 = {68, 69, 70, 71, 72, 73}; //Gap for duid 114-115
    private static final int[] INFO_13 = {76, 77, 78, 79, 80, 81};
    private static final int[] INFO_14 = {82, 83, 84, 85, 86, 87};
    private static final int[] INFO_15 = {88, 89, 90, 91, 92, 93};
    private static final int[] INFO_16 = {94, 95, 96, 97, 98, 99};
    private static final int[] INFO_17 = {100, 101, 102, 103, 104, 105};
    private static final int[] INFO_18 = {106, 107, 108, 109, 110, 111};
    private static final int[] INFO_19 = {112, 113, 114, 115, 116, 117};
    private static final int[] INFO_20 = {118, 119, 120, 121, 122, 123};
    private static final int[] INFO_21 = {124, 125, 126, 127, 128, 129};
    private static final int[] INFO_22 = {130, 131, 132, 133, 134, 135};
    private static final int[] INFO_23 = {136, 137, 138, 139, 140, 141};
    private static final int[] INFO_24 = {142, 143, 144, 145, 146, 147};
    private static final int[] INFO_25 = {148, 149, 150, 151, 152, 153};
    private static final int[] INFO_26 = {154, 155, 156, 157, 158, 159};
    private static final int[] INFO_27 = {160, 161, 162, 163, 164, 165};
    private static final int[] INFO_28 = {166, 167, 168, 169, 170, 171};
    private static final int[] INFO_29 = {172, 173, 174, 175, 176, 177};
    private static final int[] INFO_30 = {178, 179, 180, 181, 182, 183};
    private static final int[] PARITY_1 = {184, 185, 186, 187, 188, 189};
    private static final int[] PARITY_2 = {190, 191, 192, 193, 194, 195};
    private static final int[] PARITY_3 = {196, 197, 198, 199, 200, 201};
    private static final int[] PARITY_4 = {202, 203, 204, 205, 206, 207};
    private static final int[] PARITY_5 = {208, 209, 210, 211, 212, 213};
    private static final int[] PARITY_6 = {214, 215, 216, 217, 218, 219};
    private static final int[] PARITY_7 = {220, 221, 222, 223, 224, 225};
    private static final int[] PARITY_8 = {226, 227, 228, 229, 230, 231};
    private static final int[] PARITY_9 = {232, 233, 234, 235, 236, 237};
    private static final int[] PARITY_10 = {238, 239, 240, 241, 242, 243}; //Gap for duid 284-285
    private static final int[] PARITY_11 = {246, 247, 248, 249, 250, 251};
    private static final int[] PARITY_12 = {252, 253, 254, 255, 256, 257};
    private static final int[] PARITY_13 = {258, 259, 260, 261, 262, 263};
    private static final int[] PARITY_14 = {264, 265, 266, 267, 268, 269};
    private static final int[] PARITY_15 = {270, 271, 272, 273, 274, 275};
    private static final int[] PARITY_16 = {276, 277, 278, 279, 280, 281};
    private static final int[] PARITY_17 = {282, 283, 284, 285, 286, 287};
    private static final int[] PARITY_18 = {288, 289, 290, 291, 292, 293};
    private static final int[] PARITY_19 = {294, 295, 296, 297, 298, 299};
    private static final int[] PARITY_20 = {300, 301, 302, 303, 304, 305};
    private static final int[] PARITY_21 = {306, 307, 308, 309, 310, 311};
    private static final int[] PARITY_22 = {312, 313, 314, 315, 316, 317};

    private List<MacMessage> mMacMessages;

    /**
     * Constructs a scrambled SACCH timeslot
     *
     * @param message containing 320 scrambled bits for the timeslot
     * @param scramblingSequence to descramble the message
     * @param timeslot of the message
     * @param timestamp of the message
     */
    public SacchTimeslot(CorrectedBinaryMessage message, BinaryMessage scramblingSequence, int timeslot,
                         long timestamp)
    {
        super(message, DataUnitID.SCRAMBLED_SACCH, scramblingSequence, timeslot, timestamp);
    }

    /**
     * Constructs an un-scrambled SACCH timeslot
     *
     * @param message containing 320 scrambled bits for the timeslot
     * @param timeslot of the message
     * @param timestamp of the message
     */
    public SacchTimeslot(CorrectedBinaryMessage message, int timeslot, long timestamp)
    {
        super(message, DataUnitID.UNSCRAMBLED_SACCH, timeslot, timestamp);
    }

    public Voice4VOffset getOffsetToNextVoice4VStart()
    {
        return MacMessage.getOffsetToNextVoice4VStart(getMessage());
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("TS").append(getTimeslot());

        if(getDataUnitID() == DataUnitID.UNSCRAMBLED_SACCH)
        {
            sb.append(" SA-UN");
            sb.append(" ").append(getMacMessages().toString());
        }
        else
        {
            sb.append(" SA-SC");
            sb.append(" ").append(getMacMessages().toString());
        }


        return sb.toString();
    }

    /**
     * Information Outbound Encoded MAC Information (I-OEMI) message(s) carried by this timeslot
     */
    @Override
    public List<MacMessage> getMacMessages()
    {
        if(mMacMessages == null)
        {
            int[] input = new int[63];
            int[] output = new int[63];

//            input[0] = 0; //Punctured
//            input[1] = 0; //Punctured
//            input[2] = 0; //Punctured
//            input[3] = 0; //Punctured
//            input[4] = 0; //Punctured
//            input[5] = 0; //Punctured
            input[6] = getMessage().getInt(PARITY_22);
            input[7] = getMessage().getInt(PARITY_21);
            input[8] = getMessage().getInt(PARITY_20);
            input[9] = getMessage().getInt(PARITY_19);
            input[10] = getMessage().getInt(PARITY_18);
            input[11] = getMessage().getInt(PARITY_17);
            input[12] = getMessage().getInt(PARITY_16);
            input[13] = getMessage().getInt(PARITY_15);
            input[14] = getMessage().getInt(PARITY_14);
            input[15] = getMessage().getInt(PARITY_13);
            input[16] = getMessage().getInt(PARITY_12);
            input[17] = getMessage().getInt(PARITY_11);
            input[18] = getMessage().getInt(PARITY_10);
            input[19] = getMessage().getInt(PARITY_9);
            input[20] = getMessage().getInt(PARITY_8);
            input[21] = getMessage().getInt(PARITY_7);
            input[22] = getMessage().getInt(PARITY_6);
            input[23] = getMessage().getInt(PARITY_5);
            input[24] = getMessage().getInt(PARITY_4);
            input[25] = getMessage().getInt(PARITY_3);
            input[26] = getMessage().getInt(PARITY_2);
            input[27] = getMessage().getInt(PARITY_1);
            input[28] = getMessage().getInt(INFO_30);
            input[29] = getMessage().getInt(INFO_29);
            input[30] = getMessage().getInt(INFO_28);
            input[31] = getMessage().getInt(INFO_27);
            input[32] = getMessage().getInt(INFO_26);
            input[33] = getMessage().getInt(INFO_25);
            input[34] = getMessage().getInt(INFO_24);
            input[35] = getMessage().getInt(INFO_23);
            input[36] = getMessage().getInt(INFO_22);
            input[37] = getMessage().getInt(INFO_21);
            input[38] = getMessage().getInt(INFO_20);
            input[39] = getMessage().getInt(INFO_19);
            input[40] = getMessage().getInt(INFO_18);
            input[41] = getMessage().getInt(INFO_17);
            input[42] = getMessage().getInt(INFO_16);
            input[43] = getMessage().getInt(INFO_15);
            input[44] = getMessage().getInt(INFO_14);
            input[45] = getMessage().getInt(INFO_13);
            input[46] = getMessage().getInt(INFO_12);
            input[47] = getMessage().getInt(INFO_11);
            input[48] = getMessage().getInt(INFO_10);
            input[49] = getMessage().getInt(INFO_9);
            input[50] = getMessage().getInt(INFO_8);
            input[51] = getMessage().getInt(INFO_7);
            input[52] = getMessage().getInt(INFO_6);
            input[53] = getMessage().getInt(INFO_5);
            input[54] = getMessage().getInt(INFO_4);
            input[55] = getMessage().getInt(INFO_3);
            input[56] = getMessage().getInt(INFO_2);
            input[57] = getMessage().getInt(INFO_1);
//            input[58] = 0; //Shortened
//            input[59] = 0; //Shortened
//            input[60] = 0; //Shortened
//            input[61] = 0; //Shortened
//            input[62] = 0; //Shortened

            ReedSolomon_63_35_29_P25 reedSolomon_63_35_29 = new ReedSolomon_63_35_29_P25();

            boolean irrecoverableErrors;

            try
            {
                irrecoverableErrors = reedSolomon_63_35_29.decode(input, output);
            }
            catch(Exception e)
            {
                irrecoverableErrors = true;
            }

            CorrectedBinaryMessage binaryMessage = new CorrectedBinaryMessage(180);

            int pointer = 0;

            for(int x = 57; x >= 28; x--)
            {
                if(output[x] != -1)
                {
                    binaryMessage.load(pointer, 6, output[x]);
                }

                pointer += 6;
            }

            mMacMessages = MacMessageFactory.create(getTimeslot(), getDataUnitID(), binaryMessage, getTimestamp());

            if(irrecoverableErrors)
            {
                mMacMessages.clear();
                MacMessage macMessage = new UnknownMacMessage(getTimeslot(), getDataUnitID(), binaryMessage, getTimestamp());
                macMessage.setValid(false);
                mMacMessages.add(macMessage);
            }
            else
            {
                //If we corrected any bit errors, update the original message with the bit error count
                for(int x = 0; x <= 57; x++)
                {
                    if(output[x] != input[x])
                    {
                        binaryMessage.incrementCorrectedBitCount(Integer.bitCount((output[x] ^ input[x])));
                    }
                }
            }

        }

        return mMacMessages;
    }
}
