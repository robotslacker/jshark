package com.jshark;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 共用命令行语法层 {@link CliArgs} 的契约测试。
 *
 * <p>三个入口的 {@code --k=v}/裸值/可选值/错误文案都走这里，任何一处漂移都会直接改变
 * CLI 行为，因此用纯单元测试把它钉住（不启动进程、不做字段绑定）。</p>
 */
class CliArgsTest {

    /** 测试用选项元数据。 */
    private record Spec(String fieldName, boolean requiresValue, boolean valueOptional)
            implements CliArgs.Spec {
    }

    private static final Map<String, Spec> OPTIONS = Map.of(
            "--value", new Spec("value", true, false),
            "--flag", new Spec("flag", false, false),
            "--optional", new Spec("optional", true, true));

    @Test
    void equalsFormKeepsEverythingAfterFirstEquals() {
        List<CliArgs.Entry<Spec>> entries = CliArgs.parse(
                new String[] {"--value=a=b"}, OPTIONS);
        assertEquals(1, entries.size());
        assertEquals("--value", entries.get(0).name());
        assertEquals("a=b", entries.get(0).value());
    }

    @Test
    void separateTokenIsUsedAsValue() {
        List<CliArgs.Entry<Spec>> entries = CliArgs.parse(
                new String[] {"--value", "-1"}, OPTIONS);
        assertEquals("-1", entries.get(0).value(), "负数是合法取值，不能当成短选项");
    }

    @Test
    void bareFlagHasNoValue() {
        List<CliArgs.Entry<Spec>> entries = CliArgs.parse(new String[] {"--flag"}, OPTIONS);
        assertNull(entries.get(0).value());
    }

    @Test
    void optionalValueDefaultsToTrue() {
        assertEquals("true", CliArgs.parse(new String[] {"--optional"}, OPTIONS).get(0).value());
        List<CliArgs.Entry<Spec>> entries = CliArgs.parse(
                new String[] {"--optional", "--flag"}, OPTIONS);
        assertEquals("true", entries.get(0).value(),
                "下一个 token 是另一个选项时，可选取值按 true 处理");
        assertEquals("--flag", entries.get(1).name(), "被跳过的选项仍要正常解析");
    }

    @Test
    void missingRequiredValueFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CliArgs.parse(new String[] {"--value"}, OPTIONS));
        assertEquals("Option --value requires a value", e.getMessage());
    }

    @Test
    void unknownShortAndStrayArgumentsFailWithUnchangedMessages() {
        assertEquals("Unknown option: --nope",
                assertThrows(IllegalArgumentException.class,
                        () -> CliArgs.parse(new String[] {"--nope"}, OPTIONS)).getMessage());
        assertEquals("Short option -x is not supported. Please use the corresponding long option.",
                assertThrows(IllegalArgumentException.class,
                        () -> CliArgs.parse(new String[] {"-x"}, OPTIONS)).getMessage());
        assertEquals("Unexpected argument: stray (only long options starting with -- are supported)",
                assertThrows(IllegalArgumentException.class,
                        () -> CliArgs.parse(new String[] {"stray"}, OPTIONS)).getMessage());
    }

    @Test
    void entriesKeepCommandLineOrder() {
        List<CliArgs.Entry<Spec>> entries = CliArgs.parse(
                new String[] {"--flag", "--value", "x", "--flag"}, OPTIONS);
        assertEquals(List.of("--flag", "--value", "--flag"),
                entries.stream().map(CliArgs.Entry::name).toList());
    }
}
