package com.jshark.parser;

/**
 * 互联网校验和计算（IPv4 头校验和、TCP/UDP 伪首部校验和）。
 *
 * <h3>约定</h3>
 * <ul>
 *   <li>全部按 16 位大端字做反码求和，结果已做进位折叠。</li>
 *   <li>{@link #compute} 返回的是**要写入校验和字段的值**；把它写进字段后再对整段求和应得 {@code 0xFFFF}，
 *       因此 {@link #verify} 的判据是"对**含校验和字段**的数据求和后，其反码为 0"，即
 *       {@code compute(整段) == 0}。</li>
 *   <li>UDP 的"校验和为 0"表示发送方未计算校验和（IPv4 允许）。
 *       这种包在改写端口时必须**保持 0**，而不是写入一个新值——否则对端会按 IPv4 强校验和去验证，
 *       一旦计算路径与发送方不同就会被丢弃。TCP 的校验和是强制的，恒为 0 只可能是真实错误。</li>
 * </ul>
 */
public final class IpChecksum {

    private IpChecksum() {
    }

    /**
     * 计算反码校验和。
     *
     * @param data   待计算数据
     * @param offset 起始偏移
     * @param length 长度（字节）
     * @return 16 位校验和（已折叠进位）
     */
    public static int compute(byte[] data, int offset, int length) {
        long sum = 0;
        int end = offset + length;
        int i = offset;
        // 16 位字逐字累加
        for (; i + 1 < end; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        // 奇数长度：最后一个字节按高位补齐
        if (i < end) {
            sum += (data[i] & 0xFF) << 8;
        }
        return fold(sum);
    }

    /**
     * 计算两段数据拼接后的反码校验和（用于"伪首部 + 传输层"）。
     *
     * @param a    第一段
     * @param aOff 第一段起始偏移
     * @param aLen 第一段长度
     * @param b    第二段
     * @param bOff 第二段起始偏移
     * @param bLen 第二段长度
     * @return 16 位校验和
     */
    public static int compute(byte[] a, int aOff, int aLen, byte[] b, int bOff, int bLen) {
        long sum = 0;
        int endA = aOff + aLen;
        int i = aOff;
        for (; i + 1 < endA; i += 2) {
            sum += ((a[i] & 0xFF) << 8) | (a[i + 1] & 0xFF);
        }
        // aLen 为奇数时，把 a 的最后一个字节与 b 的第一个字节拼成一个 16 位字
        int carryByte = -1;
        if (i < endA) {
            carryByte = a[i] & 0xFF;
        }

        int j = bOff;
        int endB = bOff + bLen;
        if (carryByte >= 0 && j < endB) {
            sum += (carryByte << 8) | (b[j] & 0xFF);
            j++;
        } else if (carryByte >= 0) {
            sum += carryByte << 8;
        }
        for (; j + 1 < endB; j += 2) {
            sum += ((b[j] & 0xFF) << 8) | (b[j + 1] & 0xFF);
        }
        if (j < endB) {
            sum += (b[j] & 0xFF) << 8;
        }
        return fold(sum);
    }

    /**
     * 校验一段包含校验和字段的数据是否自洽。
     * <p>
     * 判据：对整段（含校验和字段）求校验和，若结果为 {@code 0} 则自洽
     * （因为此时"含字段求和"恰为 {@code 0xFFFF}）。
     * </p>
     *
     * @param data   数据
     * @param offset 起始偏移
     * @param length 长度
     * @return true 表示校验通过
     */
    public static boolean verify(byte[] data, int offset, int length) {
        return compute(data, offset, length) == 0;
    }

    /**
     * 以 32 位补码加法折叠进位。
     * <p>
     * 注意：{@code 0xFFFF} 是一个合法且常见的结果（校验通过时正是它），
     * 因此循环条件是 {@code > 0xFFFF} 而不是 {@code >> 16 != 0}——
     * 后者会把 {@code 0xFFFF} 再折叠一次得到 {@code 0x0000}，导致"校验通过"被误判为不通过。
     * </p>
     *
     * @param sum 累加和
     * @return 折叠后的 16 位校验和
     */
    private static int fold(long sum) {
        while (sum > 0xFFFFL) {
            sum = (sum & 0xFFFFL) + (sum >>> 16);
        }
        return (int) (~sum & 0xFFFFL);
    }
}
