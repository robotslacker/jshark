package com.jshark.parser;

/**
 * DB 重放模式解析：把 {@code --replayMode} / {@code --injectInterface} 解析成实际模式。
 *
 * <p>这段规则原来在 {@code CliReplay} 里，{@code SourceInspector} 又按自己的启发式
 * 重新推导了一遍（inspect 的 {@code followSupported}）。两处规则一旦分叉，
 * UI 就会显示与实际重放不一致的“是否支持跟随”。现在只有这一份实现：
 * 重放侧与 {@code --inspect} 侧都调用 {@link #resolveDb(String, boolean, boolean)}。</p>
 *
 * <h3>规则（默认 payload）</h3>
 * <ul>
 *   <li><b>未显式指定</b>（默认）：一律 payload。即使给了 --injectInterface 也忽略并告警，
 *       需要按帧重放请显式写 {@code --replayMode=frame --injectInterface=<IP>}。</li>
 *   <li><b>显式 payload</b>：payload 胜出；即使给了 --injectInterface 也忽略并告警。</li>
 *   <li><b>显式 frame</b>：必须有 --injectInterface；缺失直接报错，已视为用户明确要求。</li>
 *   <li>非法模式值：报错（不再静默按 payload 处理）。</li>
 * </ul>
 */
public final class ReplayModeResolver {

    /** DB 重放的有效模式。 */
    public enum Mode {
        FRAME,
        PAYLOAD
    }

    /**
     * 解析结果：有效模式 + 需要打印的告警/错误。
     *
     * @param mode    有效模式；出错时为 null
     * @param warning 需要打印的告警（可为 null）
     * @param error   需要抛出的错误（可为 null）
     */
    public record Decision(Mode mode, String warning, String error) {
    }

    private ReplayModeResolver() {
    }

    /**
     * 解析 DB 重放模式。
     *
     * @param replayMode         --replayMode 的取值（默认 "payload"）
     * @param modeExplicit       用户是否显式给出 --replayMode
     * @param hasInjectInterface 是否给出非空的 --injectInterface
     * @return 解析结果
     */
    public static Decision resolveDb(String replayMode,
                                     boolean modeExplicit,
                                     boolean hasInjectInterface) {
        // 未显式指定 = 默认 payload：与 PCAP 路径、UI（默认选 payload）保持一致。
        if (!modeExplicit) {
            if (hasInjectInterface) {
                // 用户给了网卡却没给模式：默认仍是 payload，网卡被忽略并明确告警。
                return new Decision(Mode.PAYLOAD,
                        "[JShark] default replay mode is 'payload'; --injectInterface is ignored "
                                + "(use --replayMode=frame --injectInterface=<IP> for frame replay)",
                        null);
            }
            return new Decision(Mode.PAYLOAD, null, null);
        }

        String mode = replayMode == null ? "" : replayMode.trim();
        if (mode.equalsIgnoreCase("frame")) {
            if (hasInjectInterface) {
                return new Decision(Mode.FRAME, null, null);
            }
            return new Decision(null, null,
                    "--replayMode=frame requires --injectInterface=<IP of the NIC to inject on>.");
        }
        if (mode.equalsIgnoreCase("payload")) {
            if (hasInjectInterface) {
                return new Decision(Mode.PAYLOAD,
                        "[JShark] --injectInterface is ignored in 'payload' replay mode",
                        null);
            }
            return new Decision(Mode.PAYLOAD, null, null);
        }
        return new Decision(null, null,
                "Invalid --replayMode: " + replayMode + " (expected 'frame' or 'payload')");
    }

    /**
     * 便捷判断：按同一套规则，DB 重放实际是否走 payload。
     *
     * <p>供 {@code --inspect} 判断“是否支持跟随（follow）”使用，避免在 inspect 侧
     * 重新推导一份可能分叉的启发式。</p>
     *
     * @param replayMode         --replayMode 的取值
     * @param modeExplicit       用户是否显式给出 --replayMode
     * @param hasInjectInterface 是否给出非空的 --injectInterface
     * @return true 表示实际走 payload 模式（非法模式按非 payload 处理）
     */
    public static boolean effectivePayload(String replayMode,
                                           boolean modeExplicit,
                                           boolean hasInjectInterface) {
        return resolveDb(replayMode, modeExplicit, hasInjectInterface).mode() == Mode.PAYLOAD;
    }
}
