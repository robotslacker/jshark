package com.jshark;

/**
 * 端到端探针（<b>不是</b>测试用例，surefire 不会执行它）：
 * 在一个真实进程里跑 {@link CliShark#main}，然后调用 {@code System.exit(0)}。
 *
 * <p>为什么要它：{@code System.exit} 与 Ctrl+C 走的是<b>同一套</b> JVM 关闭流程
 * （执行 shutdown hook、hook 全部返回后进程退出）。用它可以验证真实场景下的
 * "最后一卷 FORCE CHECKPOINT + 更名"是否成立——包括 hook 的预算等待与兜底接管，
 * 而这些是单元测试覆盖不到的部分。</p>
 *
 * <p>用法：{@code java -cp ... com.jshark.HookExitProbe <ip> <logdb> <splitMs> <runMs>}</p>
 */
public final class HookExitProbe {

    private HookExitProbe() {
    }

    public static void main(String[] args) throws Exception {
        String ip = args[0];
        String logDb = args[1];
        String split = args[2];
        long runMs = Long.parseLong(args[3]);

        Thread capture = new Thread(() -> {
            try {
                CliShark.main(new String[] {
                        "--ip_address=" + ip,
                        "--logdb=" + logDb,
                        "--split=" + split
                });
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }, "probe-capture");
        capture.setDaemon(false);
        capture.start();

        Thread.sleep(runMs);
        System.out.println("[probe] === System.exit(0): 触发与 Ctrl+C 相同的 shutdown 流程 ===");
        System.exit(0);
    }
}
