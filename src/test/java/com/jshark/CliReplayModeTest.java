package com.jshark;

import com.jshark.parser.ReplayModeResolver;
import com.jshark.parser.ReplayModeResolver.Decision;
import com.jshark.parser.ReplayModeResolver.Mode;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 重放模式解析的回归测试（默认 payload）。
 *
 * <p>钉住一次真实 bug：历史实现里只要给了 {@code --injectInterface} 就强制 frame，
 * 导致 {@code --replayMode=payload --injectInterface=IP} 仍跑 frame，显式 payload 被静默忽略。
 * 现在的规则（见 {@link ReplayModeResolver#resolveDb(String, boolean, boolean)}）：
 * <ul>
 *   <li>默认（未显式指定）为 payload —— 与 PCAP 路径、UI 保持一致；给 --injectInterface 也忽略并告警。</li>
 *   <li>显式 frame 必须有 --injectInterface，缺失直接报错。</li>
 *   <li>显式 payload 恒为 payload，--injectInterface 忽略并告警。</li>
 * </ul>
 * {@code --inspect} 的 followSupported 也复用同一实现。</p>
 */
public class CliReplayModeTest {

    @Test
    void defaultModeWithoutInjectIsPayload() {
        Decision decision = ReplayModeResolver.resolveDb("payload", false, false);

        assertEquals(Mode.PAYLOAD, decision.mode());
        assertNull(decision.error());
        assertNull(decision.warning());
    }

    @Test
    void defaultModeWithInjectStillPayloadAndWarnsIgnored() {
        // 默认就是 payload：即使给了网卡也回到 payload，而不是被升成 frame。
        Decision decision = ReplayModeResolver.resolveDb("payload", false, true);

        assertEquals(Mode.PAYLOAD, decision.mode());
        assertNull(decision.error());
        assertNotNull(decision.warning());
        assertTrue(decision.warning().contains("ignored"),
                "默认 payload 下网卡应被忽略并告警: " + decision.warning());
    }

    @Test
    void notExplicitFrameStringStillResolvesToPayload() {
        // 防御性：即便传进来的是 "frame"，只要没有显式标记，就按默认 payload 处理。
        Decision decision = ReplayModeResolver.resolveDb("frame", false, false);

        assertEquals(Mode.PAYLOAD, decision.mode());
        assertNull(decision.error());
    }

    @Test
    void explicitFrameWithInjectIsFrame() {
        Decision decision = ReplayModeResolver.resolveDb("frame", true, true);

        assertEquals(Mode.FRAME, decision.mode());
        assertNull(decision.error());
        assertNull(decision.warning());
    }

    @Test
    void explicitFrameWithoutInjectIsErrorInsteadOfSilentFallback() {
        Decision decision = ReplayModeResolver.resolveDb("frame", true, false);

        assertNull(decision.mode());
        assertNotNull(decision.error());
        assertTrue(decision.error().contains("requires --injectInterface"),
                "显式 frame 缺 inject 应报错: " + decision.error());
    }

    @Test
    void explicitPayloadWithoutInjectIsPayload() {
        Decision decision = ReplayModeResolver.resolveDb("payload", true, false);

        assertEquals(Mode.PAYLOAD, decision.mode());
        assertNull(decision.error());
        assertNull(decision.warning());
    }

    @Test
    void explicitPayloadWithInjectStaysPayloadAndWarnsInjectIgnored() {
        // 这是历史 bug 的核心用例：inject 不得再覆盖显式 payload。
        Decision decision = ReplayModeResolver.resolveDb("payload", true, true);

        assertEquals(Mode.PAYLOAD, decision.mode());
        assertNull(decision.error());
        assertNotNull(decision.warning());
        assertTrue(decision.warning().contains("ignored in 'payload'"),
                "显式 payload 下 inject 应被忽略并告警: " + decision.warning());
    }

    @Test
    void invalidModeIsErrorInsteadOfSilentlyPayload() {
        Decision decision = ReplayModeResolver.resolveDb("bogus", true, false);

        assertNull(decision.mode());
        assertNotNull(decision.error());
        assertTrue(decision.error().contains("Invalid --replayMode"),
                "非法模式应报错: " + decision.error());
    }

    @Test
    void modeParsingIsCaseInsensitive() {
        assertEquals(Mode.FRAME, ReplayModeResolver.resolveDb("FRAME", true, true).mode());
        assertEquals(Mode.PAYLOAD, ReplayModeResolver.resolveDb("Payload", true, false).mode());
    }

    @Test
    void effectivePayloadMatchesResolvedMode() {
        assertTrue(ReplayModeResolver.effectivePayload("payload", false, false),
                "默认（payload）就是 effective payload（inspect 的 followSupported 依赖它）");
        assertTrue(ReplayModeResolver.effectivePayload("payload", true, true));
        assertEquals(false, ReplayModeResolver.effectivePayload("frame", true, true));
        assertEquals(false, ReplayModeResolver.effectivePayload("bogus", true, false),
                "非法模式不应被当成 payload");
    }

    @Test
    void parserMarksReplayModeAsExplicit() throws Exception {
        CliReplay cli = new CliReplay();
        Method setFieldValue = CliReplay.class.getDeclaredMethod(
                "setFieldValue", String.class, String.class);
        setFieldValue.setAccessible(true);
        setFieldValue.invoke(cli, "replayMode", "payload");

        Field explicit = CliReplay.class.getDeclaredField("replayModeExplicit");
        explicit.setAccessible(true);
        assertTrue(explicit.getBoolean(cli),
                "显式 --replayMode 必须被标记，否则显式 frame 缺 inject 会错误地走默认（payload）");
    }
}
