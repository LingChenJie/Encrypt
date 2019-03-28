package com.jc.encrypt.hex;

public class BytesUtil {

    /**
     * 字节数组转换为16进制字符串
     *
     * @param paramArrayOfByte
     * @return
     */
    public static String bytes2HexStr(byte[] paramArrayOfByte) {
        StringBuilder localStringBuilder = new StringBuilder();
        int i = paramArrayOfByte.length;
        for (int j = 0; ; j++) {
            if (j >= i) {
                return localStringBuilder.toString().toUpperCase();
            }
            String str = Integer.toHexString(0xFF & paramArrayOfByte[j]);
            if (str.length() == 1) {
                localStringBuilder.append('0');
            }
            localStringBuilder.append(str);
        }
    }

    /**
     * 16进制字符串转为字节数组
     *
     * @param paramString
     * @return
     */
    public static byte[] hexStr2Bytes(String paramString) {
        byte[] arrayOfByte = new byte[(1 + paramString.length()) / 2];
        if ((0x1 & paramString.length()) == 1) {
            paramString = paramString + "0";
        }
        for (int i = 0; ; i++) {
            if (i >= arrayOfByte.length) {
                return arrayOfByte;
            }
            arrayOfByte[i] = ((byte) (hex2byte(paramString.charAt(1 + i * 2)) | hex2byte(paramString.charAt(i * 2)) << 4));
        }
    }

    private static byte hex2byte(char paramChar) {
        if ((paramChar <= 'f') && (paramChar >= 'a')) {
            return (byte) (10 + (paramChar - 'a'));
        }
        if ((paramChar <= 'F') && (paramChar >= 'A')) {
            return (byte) (10 + (paramChar - 'A'));
        }
        if ((paramChar <= '9') && (paramChar >= '0')) {
            return (byte) (paramChar - '0');
        }
        return 0;
    }

}
