package com.jshark;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * 三个入口共用的命令行语法层。
 *
 * <h3>只做"切分"，不做"绑定"</h3>
 * <p>
 * 它只回答"这条命令行里出现了哪些选项、各自的值是什么"，不碰任何业务字段：
 * 字段映射、取值校验仍然由各 CLI 自己的 {@code setFieldValue}/{@code setBooleanField} 完成。
 * 这样既统一了 {@code --k=v} / {@code --k v} / 裸开关 / 可选值 / 未知选项 / 短选项的规则，
 * 又不会把三个入口的选项表和业务语义硬塞进一个"万能 Config"。
 * </p>
 *
 * <h3>规则（与历史行为一致）</h3>
 * <ul>
 *   <li>{@code --opt=value}：取第一个 {@code =} 之后的部分，值里可以再含 {@code =}；</li>
 *   <li>{@code --opt value}：下一个 token 不以 {@code --} 开头才算值（因此负数是合法取值）；</li>
 *   <li>裸开关：值为 null；可选值选项裸写时值为 {@code "true"}；</li>
 *   <li>位置参数/短选项：报错，并给出与旧实现相同的提示文案。</li>
 * </ul>
 */
final class CliArgs {

    private CliArgs() {
    }

    /** 一个选项的语法元数据（由各 CLI 的 {@code OptionInfo} 实现）。 */
    interface Spec {
        /** @return 目标字段名（仅用于调用方绑定，解析器不解释） */
        String fieldName();

        /** @return 是否要求取值（false = 纯开关） */
        boolean requiresValue();

        /** @return 裸写时是否允许省略取值（省略按 "true" 处理） */
        boolean valueOptional();

        /** @return 是否隐藏（仍可解析，但不出现在 {@code --help} 里） */
        default boolean hidden() {
            return false;
        }

        /** @return 帮助文本；没有则为空串 */
        default String description() {
            return "";
        }
    }

    /**
     * 一次出现的选项。
     *
     * @param name  选项名（含前导 {@code --}）
     * @param spec  选项元数据
     * @param value 取值；裸开关为 null，可选值选项裸写为 "true"
     * @param <S>   选项元数据类型
     */
    record Entry<S extends Spec>(String name, S spec, String value) {
    }

    /**
     * 解析命令行（无旧名提示）。
     *
     * @param args    原始参数
     * @param options 选项表（键含前导 {@code --}）
     * @return 按出现顺序排列的条目
     * @throws IllegalArgumentException 未知选项、缺值、短选项或多余的位置参数
     */
    static <S extends Spec> List<Entry<S>> parse(String[] args, Map<String, S> options) {
        return parse(args, options, null);
    }

    /**
     * 解析命令行。
     *
     * @param args        原始参数
     * @param options     选项表（键含前导 {@code --}）
     * @param unknownHint 未知选项的补充说明（返回 null 表示没有）；用于 {@code --startc} 这类旧名提示
     * @return 按出现顺序排列的条目
     * @throws IllegalArgumentException 未知选项、缺值、短选项或多余的位置参数
     */
    static <S extends Spec> List<Entry<S>> parse(String[] args, Map<String, S> options,
                                                Function<String, String> unknownHint) {
        List<Entry<S>> entries = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                if (arg.startsWith("-")) {
                    throw new IllegalArgumentException("Short option " + arg
                            + " is not supported. Please use the corresponding long option.");
                }
                throw new IllegalArgumentException("Unexpected argument: " + arg
                        + " (only long options starting with -- are supported)");
            }

            String name = arg;
            String value = null;
            int eq = arg.indexOf('=');
            if (eq > 0) {
                name = arg.substring(0, eq);
                value = arg.substring(eq + 1);
            }

            S spec = options.get(name);
            if (spec == null) {
                String hint = unknownHint == null ? null : unknownHint.apply(name);
                throw new IllegalArgumentException(hint != null ? hint : "Unknown option: " + name);
            }

            if (spec.requiresValue() && value == null) {
                if (i + 1 >= args.length || args[i + 1].startsWith("--")) {
                    if (!spec.valueOptional()) {
                        throw new IllegalArgumentException("Option " + name + " requires a value");
                    }
                    // 裸写 --daemon 等价于 --daemon true
                    value = "true";
                } else {
                    value = args[++i];
                }
            }
            entries.add(new Entry<>(name, spec, value));
        }
        return entries;
    }

    /**
     * 帮助文本的选项表顺序：注册顺序必须稳定。
     *
     * @param <S> 选项元数据
     * @return 保持插入顺序的 Map
     */
    static <S> Map<String, S> stableOptions() {
        return new LinkedHashMap<>();
    }
}
