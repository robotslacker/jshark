package com.jshark;

import java.io.PrintStream;
import java.util.Map;

/**
 * 帮助文本的选项表渲染（三个入口共用）。
 *
 * <p>对齐规则只有一条：选项列宽 28、说明换行后按同一列缩进、隐藏选项跳过。
 * 之前 {@link CliShark} 与 {@link CliReplay} 各写了一份（其中 Replay 还靠硬编码选项名
 * 隐藏 {@code --inspect/--control}），改一次格式要改两处。</p>
 */
final class CliHelp {

    private static final int OPTION_COLUMN = 28;

    private CliHelp() {
    }

    /**
     * 打印选项表（不含标题/用例）。
     *
     * @param out     输出目标
     * @param options 选项表；顺序由 Map 的迭代顺序决定（入口使用 {@link CliArgs#stableOptions()}）
     */
    static void printOptions(PrintStream out, Map<String, ? extends CliArgs.Spec> options) {
        for (Map.Entry<String, ? extends CliArgs.Spec> entry : options.entrySet()) {
            String option = entry.getKey();
            CliArgs.Spec info = entry.getValue();
            if (info.hidden()) {
                continue;
            }
            String optDisplay = !info.requiresValue() ? option
                    : (info.valueOptional() ? option + " [<value>]" : option + " <value>");
            String indent = String.format("  %-" + OPTION_COLUMN + "s ", "");
            String desc = info.description().replace("\n", "\n" + indent);
            out.printf("  %-" + OPTION_COLUMN + "s %s%n", optDisplay, desc);
        }
    }
}
