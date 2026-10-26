package com.jshark;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 文件表每行完成度状态（{@link ReplayUi#fileProgressByRow}）的纯逻辑测试。
 *
 * <p>不碰 Swing、不 spawn 子进程，因此在无头环境也能跑。</p>
 */
public class ReplayUiProgressTest {

    private static ReplayUi.FileRow file(long start, long end) {
        ReplayUi.FileRow f = new ReplayUi.FileRow();
        f.name = "volume.db";
        f.dataStart = start;
        f.dataEnd = end;
        return f;
    }

    /** 所有行都不画进度条（-1）的期望值。 */
    private static double[] none(int rows) {
        double[] states = new double[rows];
        Arrays.fill(states, -1.0);
        return states;
    }

    @Test
    void nullPlayheadMeansNoProgress() {
        assertArrayEquals(none(1), ReplayUi.fileProgressByRow(null, List.of(file(0, 1000)), null, null));
    }

    @Test
    void nullOrEmptyFilesMeanNoProgress() {
        assertArrayEquals(new double[0], ReplayUi.fileProgressByRow(10L, null, null, null));
        assertArrayEquals(new double[0], ReplayUi.fileProgressByRow(10L, List.of(), null, null));
    }

    @Test
    void fractionWithinSingleFile() {
        double[] states = ReplayUi.fileProgressByRow(250L, List.of(file(0, 1000)), null, null);
        assertEquals(0.25, states[0], 1e-9);
    }

    @Test
    void fractionIsClampedToUnitInterval() {
        ReplayUi.FileRow f = file(0, 1000);
        // playhead 早于卷首：第一卷显示 0%，表示即将从这里开始
        assertArrayEquals(new double[]{0.0},
                ReplayUi.fileProgressByRow(-500L, List.of(f), null, null));
        assertArrayEquals(new double[]{1.0},
                ReplayUi.fileProgressByRow(99_999L, List.of(f), null, null));
    }

    @Test
    void exactFileEndCountsAsCompleted() {
        assertArrayEquals(new double[]{1.0},
                ReplayUi.fileProgressByRow(1000L, List.of(file(0, 1000)), null, null));
    }

    @Test
    void multiFileSwitchesAtVolumeBoundary() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000), file(2000, 4000));
        assertArrayEquals(new double[]{0.5, -1.0},
                ReplayUi.fileProgressByRow(500L, files, null, null));

        assertArrayEquals(new double[]{1.0, 0.5},
                ReplayUi.fileProgressByRow(3000L, files, null, null));
    }

    @Test
    void gapKeepsPreviousFileCompleted() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000), file(2000, 4000));
        double[] states = ReplayUi.fileProgressByRow(1500L, files, null, null);
        assertArrayEquals(new double[]{1.0, -1.0}, states,
                "卷间空档里上一卷应显示完成，后面的卷仍未开始");
    }

    @Test
    void pastFilesStayCompletedWhileNextFilePlays() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000), file(2000, 4000));
        double[] states = ReplayUi.fileProgressByRow(3000L, files, null, null);
        assertEquals(1.0, states[0], 1e-9, "时间范围已经过去的卷必须显示完成");
        assertEquals(0.5, states[1], 1e-9);
    }

    @Test
    void backwardPlayheadResetsLaterFiles() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000), file(2000, 4000));

        // 先回放到第二卷中段：第一卷完成、第二卷进行中
        assertArrayEquals(new double[]{1.0, 0.5},
                ReplayUi.fileProgressByRow(3000L, files, null, null));

        // 往前拖回第一卷中段：第二卷必须回到“未开始”，不能残留完成/进行中状态
        assertArrayEquals(new double[]{0.5, -1.0},
                ReplayUi.fileProgressByRow(500L, files, null, null),
                "往回 seek 后，目标时间之后的文件必须重置进度状态");
    }

    @Test
    void selectedRangeDefinesProgressInsteadOfWholeVolume() {
        // 卷 0..10000，但用户只回放 8000..9000：走到 8500 时应是 50%，而不是 85%
        double[] states = ReplayUi.fileProgressByRow(
                8500L, List.of(file(0, 10000)), 8000L, 9000L);
        assertEquals(0.5, states[0], 1e-9);
    }

    @Test
    void filesOutsideSelectedRangeAreIgnored() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000), file(2000, 3000));
        // 所选窗口只落在第二卷
        assertArrayEquals(new double[]{-1.0, 0.5},
                ReplayUi.fileProgressByRow(2500L, files, 2000L, 3000L));

        // playhead 在窗口之外（第一卷）：不能把卷外的卷标成“正在回放”
        assertArrayEquals(new double[]{-1.0, 0.0},
                ReplayUi.fileProgressByRow(500L, files, 2000L, 3000L),
                "窗口外的卷保持静态文本，窗口内第一卷从 0% 开始");
    }

    @Test
    void rangeWithoutOverlapProducesNoProgress() {
        List<ReplayUi.FileRow> files = List.of(file(0, 1000));
        assertArrayEquals(new double[]{-1.0},
                ReplayUi.fileProgressByRow(500L, files, 5000L, 6000L),
                "所选窗口与所有卷都不相交时不出进度条");
    }

    @Test
    void missingRangesNeverThrow() {
        List<ReplayUi.FileRow> files = new ArrayList<>();
        ReplayUi.FileRow empty = new ReplayUi.FileRow();
        empty.name = "empty.db";
        files.add(empty);
        assertArrayEquals(new double[]{-1.0},
                ReplayUi.fileProgressByRow(123L, files, null, null),
                "没有可用卷时不出进度条");

        // 混合：首行（空卷）无范围，第二行正常 → 仍能定位，且不会 NPE
        files.add(file(100, 200));
        assertArrayEquals(new double[]{-1.0, 0.5},
                ReplayUi.fileProgressByRow(150L, files, null, null));
    }
}
